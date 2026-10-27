//! Navi22 connector color state and side-effect-free TMDS admission. DRM
//! requests never acquire the asynchronous hardware owner or perform DDC.
use super::*;
use crate::amdgpu_hdr::{colorspace_valid, HdrOutputMetadata};
use crate::amdgpu_native_kms::{ConnectorColorRequest, OutputFormatRequest, OutputRoute};

impl Kms {
    pub(super) fn set_color(&mut self, request: &ConnectorColorRequest) -> bool {
        let hdr = match request.hdr_output_metadata.as_deref() {
            Some(blob) => match HdrOutputMetadata::from_blob(blob) {
                Ok(metadata) => Some(metadata),
                Err(_) => return false,
            },
            None => None,
        };
        if !colorspace_valid(u64::from(request.colorspace)) {
            return false;
        }
        let Some(index) = connector_of(self, request.connector) else {
            return false;
        };
        let connector = &mut self.connectors[index];
        if connector.port.signal != Signal::Hdmi {
            return false;
        }
        let next = OutputSettings {
            color_format: request.color_format,
            colorspace: request.colorspace,
            hdr,
            ..connector.output
        };
        if next == connector.output {
            return false;
        }
        connector.output = next;
        true
    }

    pub(super) fn set_max_bpc(&mut self, connector: u32, bpc: u8) -> bool {
        if !(8..=16).contains(&bpc) {
            return false;
        }
        let Some(index) = connector_of(self, connector) else {
            return false;
        };
        let c = &mut self.connectors[index];
        if c.port.signal != Signal::Hdmi || c.output.max_bpc == bpc {
            return false;
        }
        c.output.max_bpc = bpc;
        true
    }

    /// Checks the exact requested mode with the same format selector enable
    /// uses, against immutable observed EDID/board limits. Requests without a
    /// mode use the committed timing or the first admitted timing. No fallback
    /// hides an explicit unsupported color format.
    pub(super) fn formats_supported(
        &self,
        requests: &[OutputFormatRequest],
        routes: &[OutputRoute],
    ) -> bool {
        for (n, route) in routes.iter().enumerate() {
            if usize::from(route.display) >= MAX_CRTCS
                || connector_of(self, route.connector).is_none()
                || routes[..n]
                    .iter()
                    .any(|r| r.display == route.display || r.connector == route.connector)
            {
                return false;
            }
        }
        requests.iter().enumerate().all(|(n, request)| {
            if requests[..n].iter().any(|r| r.connector == request.connector || r.display == request.display)
                || !routes.iter().any(|r| r.connector == request.connector && r.display == request.display)
            { return false; }
            let Some(index) = connector_of(self, request.connector) else { return false; };
            let c = &self.connectors[index];
            if c.port.signal != Signal::Hdmi || !c.lightable() { return false; }
            let max_bpc = request.max_bpc.unwrap_or(c.output.max_bpc);
            if !(8..=16).contains(&max_bpc) { return false; }
            let crtc = self.crtc_at(usize::from(request.display));
            let timing = match request.mode {
                Some(mode) => self.find_mode_at(usize::from(request.display), Some(index), &mode),
                None => crtc.filter(|c| c.route == Some(index))
                    .and_then(|c| c.requested.or_else(|| c.shown.as_ref().map(|s| s.1)))
                    .or_else(|| c.modes.first().copied()),
            };
            let Some(timing) = timing else { return false; };
            let settings = OutputSettings { max_bpc, color_format: request.color_format, ..c.output };
            crate::amdgpu_dcn30_hdmi::stream_with_settings(
                &c.edid, &timing, settings,
                crate::amdgpu_navi48_boot::limited_range(crate::amdgpu_navi48_boot::broadcast_rgb()),
                c.hdmi_limits,
            ).is_some()
        })
    }
}

pub fn request_connector_color(request: ConnectorColorRequest) {
    requested(|kms| kms.set_color(&request));
}
pub fn request_connector_max_bpc(connector: u32, bpc: u8) {
    requested(|kms| kms.set_max_bpc(connector, bpc));
}
pub fn connector_color_supported(connector: u32, colorspace: u32, hdr: bool) -> bool {
    let kms = KMS.lock();
    let Some(index) = connector_of(&kms, connector) else {
        return false;
    };
    let c = &kms.connectors[index];
    colorspace_valid(u64::from(colorspace))
        && c.port.signal == Signal::Hdmi
        && (!c.present
            || crate::amdgpu_navi48_boot::hdmi_caps(&c.edid).hdmi
            || (colorspace == 0 && !hdr))
}
pub fn output_formats_supported(requests: &[OutputFormatRequest], routes: &[OutputRoute]) -> bool {
    KMS.lock().formats_supported(requests, routes)
}
