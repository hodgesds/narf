// SPDX-License-Identifier: GPL-2.0-or-later
//! Conservative metadata admission for the exact native SDIO AP profile.
//! Native START/SCB/key/port receipts remain independently mandatory.
use super::{
    fullmac::{Family, Fullmac},
    ioctl::Direction,
    runtime::Error,
};
use core::{
    future::{poll_fn, Future},
    pin::pin,
    task::Poll,
};

pub(crate) async fn discover<R: Fullmac>(runtime: &mut R) -> Result<bool, Error> {
    if R::FAMILY != Family::Sdio || !R::PRIMARY_AP {
        return Ok(false);
    }
    let Some(original) = runtime.ap_source() else {
        return Ok(false);
    };
    original.current().map_err(|_| Error::Authority)?;
    let result = {
        let mut future = pin!(runtime.command(Direction::Get, 262, b"cap\0", 768));
        poll_fn(|cx| {
            if original.current().is_err() {
                return Poll::Ready(Err(Error::Authority));
            }
            match future.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    Poll::Ready(original.current().map_err(|_| Error::Authority).and(result))
                }
            }
        })
        .await?
    };
    let end = result.iter().position(|byte| *byte == 0);
    if end.is_none() && result.len() >= 768 {
        return Err(Error::Malformed);
    }
    let text = core::str::from_utf8(&result[..end.unwrap_or(result.len())])
        .map_err(|_| Error::Malformed)?;
    if !text.is_ascii()
        || text
            .bytes()
            .any(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
    {
        return Err(Error::Malformed);
    }
    if !text.split_ascii_whitespace().any(|token| token == "ap") {
        return Ok(false);
    }
    let mut future = pin!(runtime.command(Direction::Get, 117, &[], 4));
    let result = poll_fn(|cx| {
        if original.current().is_err() {
            return Poll::Ready(Err(Error::Authority));
        }
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                Poll::Ready(original.current().map_err(|_| Error::Authority).and(result))
            }
        }
    })
    .await?;
    Ok(result.as_slice() == 0u32.to_le_bytes())
}
