//! NLO owner, a child of passive_scan. It shares the
//! existing real channel-power and associated-domain helpers without
//! issuing an unrelated host scan to manufacture progress.
use super::*;
use crate::mt7921::{channel, wowlan_nlo};
use narf_wireless::NetDetectConfig;

pub(in crate::mt7921::firmware_transport) struct Plan {
    info: RadioInfo,
    ids: Vec<u8>,
    channels: Vec<(channel::Band, u8)>,
    active: Option<ActiveScan>,
    operating: Option<crate::mt7921::association::TxPermission>,
    six: bool,
}

impl core::fmt::Debug for Plan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NloPlan")
            .field("channels", &self.channels)
            .field("active", &self.active.is_some())
            .finish_non_exhaustive()
    }
}

impl Plan {
    pub(in crate::mt7921::firmware_transport) fn prepare<B: Backend>(
        backend: &B,
        info: RadioInfo,
        config: &NetDetectConfig,
        limits: narf_wireless::SchedScanSupport,
        operating: Option<crate::mt7921::association::TxPermission>,
    ) -> Result<Self, Error> {
        wowlan_nlo::validate_with(config, limits)?;
        let policy = (!config.probe_ssids.is_empty())
            .then(|| backend.regulatory_domain())
            .transpose()?;
        let implicit = config.frequencies_mhz.is_empty();
        let mut channels = if implicit {
            let mut channels: Vec<_> = channel::channels(info.capabilities.phy.bands)
                .into_iter()
                .filter_map(|number| channel::band(number).map(|band| (band, number)))
                .collect();
            if crate::mt7921::six_ghz::qualified(info) {
                channels
                    .extend(channel::channels_6ghz().map(|number| (channel::Band::Ghz6, number)));
            }
            channels
        } else {
            config
                .frequencies_mhz
                .iter()
                .map(|&frequency| {
                    use narf_wireless::association::channel::{from_frequency_band, Band};
                    let (band, number) = from_frequency_band(frequency).ok_or(Error::Bounds)?;
                    let band = match band {
                        Band::Ghz2 => channel::Band::Ghz2,
                        Band::Ghz5 => channel::Band::Ghz5,
                        Band::Ghz6 => channel::Band::Ghz6,
                    };
                    if channel::frequency_in(band, number) != Some(frequency)
                        || if band == channel::Band::Ghz6 {
                            !crate::mt7921::six_ghz::qualified(info)
                        } else {
                            info.capabilities.phy.bands & band.capability() == 0
                        }
                    {
                        return Err(Error::InvalidIdentity);
                    }
                    Ok((band, number))
                })
                .collect::<Result<Vec<_>, Error>>()?
        };
        if let Some(policy) = &policy {
            let permitted = |&(band, number): &(channel::Band, u8)| {
                // Like ordinary native active scan, 6GHz remains passive
                // until a real active-discovery/power-class owner exists.
                band != channel::Band::Ghz6
                    && crate::mt7921::association::TxPermission::from_domain(policy, number)
                        .is_some()
            };
            if implicit {
                channels.retain(permitted);
            } else if !channels.iter().all(permitted) {
                return Err(Error::Authority);
            }
        }
        if implicit {
            // Linux CONNAC2 clamps the default hardware list to64. Explicit
            // userspace lists exceeding that bound were rejected above.
            channels.truncate(64);
        }
        if channels.is_empty() || channels.len() > 64 {
            return Err(Error::Bounds);
        }
        let ids = channels
            .iter()
            .map(|&(band, number)| channel::rx_channel(band, number).ok_or(Error::Bounds))
            .collect::<Result<Vec<_>, _>>()?;
        let mut active = policy
            .as_ref()
            .map(|policy| ActiveScan::prepare(policy, &ids))
            .transpose()?;
        if let (Some(active), Some(operating)) = (&mut active, operating) {
            let occupied = operating.channels();
            for (number, permission) in &mut active.permissions {
                if permission.country != operating.country {
                    return Err(Error::Authority);
                }
                if permission.band() == operating.band() && occupied.contains(number) {
                    permission.power_dbm = permission.power_dbm.min(operating.power_dbm);
                }
            }
        }
        let six = channels
            .iter()
            .any(|&(band, _)| band == channel::Band::Ghz6);
        let plan = Self {
            info,
            ids,
            channels,
            active,
            operating,
            six,
        };
        plan.current(backend)?;
        Ok(plan)
    }

    /// The request's channels in scan-id (RXD channel) form.
    pub(in crate::mt7921::firmware_transport) fn scan_ids(&self) -> &[u8] {
        &self.ids
    }

    pub(in crate::mt7921::firmware_transport) fn current<B: Backend>(
        &self,
        backend: &B,
    ) -> Result<(), Error> {
        backend.check()?;
        if let Some(operating) = self.operating {
            backend.check_tx_permission(operating)?;
        }
        if let Some(active) = &self.active {
            let domain = backend.regulatory_domain()?;
            active.current(&domain, &self.ids)?;
        }
        Ok(())
    }
}

impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) async fn program_wow_nlo(
        &mut self,
        plan: &Plan,
        config: &NetDetectConfig,
    ) -> Result<(), Error> {
        plan.current(&self.backend)?;
        if let Some(active) = &plan.active {
            let mut rows = Vec::new();
            if let Some(operating) = plan.operating {
                rows.push(
                    operating
                        .rate_limits_for_paths(plan.info.capabilities.phy.spatial_streams)
                        .ok_or(Error::Bounds)?,
                );
            }
            for (_, permission) in &active.permissions {
                rows.push(
                    permission
                        .rate_limits_for_paths(plan.info.capabilities.phy.spatial_streams)
                        .ok_or(Error::Bounds)?,
                );
            }
            rows.sort_by_key(|row| row[5]);
            let count = rows.len();
            for (index, mut row) in rows.into_iter().enumerate() {
                plan.current(&self.backend)?;
                row[6] = u8::from(index + 1 == count);
                self.notify(
                    Command::Ce {
                        id: 0x5d,
                        query: false,
                    },
                    &row,
                )
                .await?;
                let mut request = [0; 8];
                request[..4].copy_from_slice(&0x820c8000u32.to_le_bytes());
                let reply = self
                    .exchange(
                        Command::Ce {
                            id: 0xc0,
                            query: true,
                        },
                        &request,
                    )
                    .await?;
                if reply.len() != 8 || reply[..4] != request[..4] {
                    return Err(Error::MalformedEvent);
                }
                plan.current(&self.backend)?;
            }
        }
        let domain = match plan.operating {
            Some(operating) => associated::associated_domain(
                plan.info,
                operating,
                plan.active.as_ref(),
                &plan.ids,
                plan.six,
            )?,
            None => match plan.active.as_ref() {
                Some(active) => active.domain(&plan.ids),
                None if plan.six => passive_domain_6ghz(plan.info),
                None => passive_domain(plan.info),
            },
        };
        plan.current(&self.backend)?;
        self.notify(
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &domain,
        )
        .await?;
        let address = config
            .random_mac
            .map(|random| {
                let mut address = [0u8; 6];
                self.backend.random_bytes(&mut address)?;
                for ((byte, supplied), mask) in address.iter_mut().zip(random.addr).zip(random.mask)
                {
                    *byte = (*byte & !mask) | (supplied & mask);
                }
                Ok::<_, Error>(address)
            })
            .transpose()?;
        let sequence = self.scan_seq % 127 + 1;
        let body = wowlan_nlo::request(config, sequence, &plan.channels, address)?;
        plan.current(&self.backend)?;
        self.scan_seq = sequence;
        self.notify(
            Command::Ce {
                id: wowlan_nlo::REQUEST,
                query: false,
            },
            &body,
        )
        .await?;
        plan.current(&self.backend)?;
        self.notify(
            Command::Ce {
                id: wowlan_nlo::ENABLE,
                query: false,
            },
            &wowlan_nlo::enable(true),
        )
        .await?;
        // Both CE commands are no-reply in Linux; their actual native DMA
        // receipts precede the ordered acknowledged WOW_CTRL START. Do not
        // invent separate firmware acknowledgements for these requests.
        plan.current(&self.backend)
    }
}
