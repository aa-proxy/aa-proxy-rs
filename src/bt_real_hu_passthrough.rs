use crate::config::AppConfig;
use crate::mitm::protos::*;
use crate::mitm::{
    get_name, ModifyContext, Packet, PacketAction, ProxyType, Result, ENCRYPTED, FRAME_TYPE_FIRST,
    FRAME_TYPE_LAST,
};
use protobuf::{Enum, Message};
use simplelog::*;

const REAL_HU_BLUETOOTH_PREFERRED_SERVICE_ID: i32 = 9;

fn looks_like_bluetooth_address(address: &str) -> bool {
    let parts: Vec<&str> = address.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()))
}

fn next_available_service_id(msg: &ServiceDiscoveryResponse, preferred: i32) -> i32 {
    if !msg.services.iter().any(|svc| svc.id() == preferred) {
        preferred
    } else {
        msg.services.iter().map(|svc| svc.id()).max().unwrap_or(0) + 1
    }
}

pub(crate) fn bt_add_real_hu_passthrough_service(
    proxy_type: ProxyType,
    ctx: &mut ModifyContext,
    msg: &mut ServiceDiscoveryResponse,
    cfg: &AppConfig,
) {
    ctx.injected_bluetooth_channel = None;

    if !cfg.bt_real_hu_passthrough_enabled {
        return;
    }

    let car_address = cfg.bt_real_hu_passthrough_address.trim();
    if car_address.is_empty() {
        warn!(
            "{} <blue>real HU Bluetooth passthrough:</> enabled but bt_real_hu_passthrough_address is empty; not advertising synthetic Bluetooth service",
            get_name(proxy_type)
        );
        return;
    }

    if !looks_like_bluetooth_address(car_address) {
        warn!(
            "{} <blue>real HU Bluetooth passthrough:</> invalid Bluetooth address <b>{}</>; expected XX:XX:XX:XX:XX:XX; not advertising synthetic Bluetooth service",
            get_name(proxy_type),
            car_address
        );
        return;
    }

    if msg
        .services
        .iter()
        .any(|svc| svc.bluetooth_service.is_some())
    {
        warn!(
            "{} <blue>real HU Bluetooth passthrough:</> SDR already contains a Bluetooth service; leaving it unchanged. Enable remove_bluetooth to replace the HU-advertised Bluetooth service with the passthrough address.",
            get_name(proxy_type)
        );
        return;
    }

    let service_id = next_available_service_id(msg, REAL_HU_BLUETOOTH_PREFERRED_SERVICE_ID);
    let Ok(channel) = u8::try_from(service_id) else {
        warn!(
            "{} <blue>real HU Bluetooth passthrough:</> chosen service id {} does not fit in a channel id; not advertising synthetic Bluetooth service",
            get_name(proxy_type),
            service_id
        );
        return;
    };

    let mut bluetooth_service = BluetoothService::new();
    bluetooth_service.set_car_address(car_address.to_ascii_uppercase());
    bluetooth_service
        .supported_pairing_methods
        .push(BluetoothPairingMethod::BLUETOOTH_PAIRING_NUMERIC_COMPARISON.into());
    bluetooth_service
        .supported_pairing_methods
        .push(BluetoothPairingMethod::BLUETOOTH_PAIRING_PIN.into());

    let mut service = Service::new();
    service.set_id(service_id);
    service.bluetooth_service = protobuf::MessageField::some(bluetooth_service);
    msg.services.push(service);

    ctx.injected_service_ids.insert(service_id);
    ctx.injected_channels.insert(channel);
    ctx.injected_bluetooth_channel = Some(channel);

    info!(
        "{} <blue>real HU Bluetooth passthrough:</> injected Bluetooth service id/channel=<b>{:#04x}</> car_address=<b>{}</> already_paired=true only",
        get_name(proxy_type),
        channel,
        car_address.to_ascii_uppercase()
    );
}

fn build_bluetooth_reply_on_channel(
    channel: u8,
    message_id: BluetoothMessageId,
    payload: Vec<u8>,
) -> Packet {
    let mut payload = payload;
    let message_id = message_id as u16;
    payload.insert(0, (message_id >> 8) as u8);
    payload.insert(1, (message_id & 0xff) as u8);

    Packet {
        channel,
        flags: ENCRYPTED | FRAME_TYPE_FIRST | FRAME_TYPE_LAST,
        final_length: None,
        payload,
    }
}

pub(crate) fn bt_maybe_handle_real_hu_passthrough_packet(
    proxy_type: ProxyType,
    pkt: &mut Packet,
    ctx: &ModifyContext,
    cfg: &AppConfig,
) -> Result<Option<PacketAction>> {
    if !cfg.bt_real_hu_passthrough_enabled || ctx.injected_bluetooth_channel != Some(pkt.channel) {
        return Ok(None);
    }

    if pkt.payload.len() < 2 {
        warn!(
            "{} <blue>real HU Bluetooth passthrough:</> dropping short Bluetooth packet on synthetic channel <b>{:#04x}</> len={}",
            get_name(proxy_type),
            pkt.channel,
            pkt.payload.len()
        );
        return Ok(Some(PacketAction::Drop));
    }

    let raw_message_id = u16::from_be_bytes([pkt.payload[0], pkt.payload[1]]);
    let Some(message_id) = BluetoothMessageId::from_i32(raw_message_id as i32) else {
        warn!(
            "{} <blue>real HU Bluetooth passthrough:</> dropping unsupported Bluetooth message id <b>{:#06x}</> on synthetic channel <b>{:#04x}</>",
            get_name(proxy_type),
            raw_message_id,
            pkt.channel
        );
        return Ok(Some(PacketAction::Drop));
    };

    match message_id {
        BluetoothMessageId::BLUETOOTH_MESSAGE_PAIRING_REQUEST => {
            match BluetoothPairingRequest::parse_from_bytes(&pkt.payload[2..]) {
                Ok(req) => info!(
                    "{} <blue>real HU Bluetooth passthrough:</> pairing request from phone=<b>{}</> method={:?}; replying already_paired=true for real HU address=<b>{}</>",
                    get_name(proxy_type),
                    req.phone_address(),
                    req.pairing_method(),
                    cfg.bt_real_hu_passthrough_address.trim().to_ascii_uppercase()
                ),
                Err(e) => warn!(
                    "{} <blue>real HU Bluetooth passthrough:</> failed to parse BluetoothPairingRequest on channel <b>{:#04x}</>: {}; replying already_paired=true anyway",
                    get_name(proxy_type),
                    pkt.channel,
                    e
                ),
            }

            let mut response = BluetoothPairingResponse::new();
            response.set_status(MessageStatus::STATUS_SUCCESS);
            response.set_already_paired(true);
            let payload = response.write_to_bytes()?;
            *pkt = build_bluetooth_reply_on_channel(
                pkt.channel,
                BluetoothMessageId::BLUETOOTH_MESSAGE_PAIRING_RESPONSE,
                payload,
            );
            Ok(Some(PacketAction::SendBack))
        }
        BluetoothMessageId::BLUETOOTH_MESSAGE_AUTHENTICATION_DATA
        | BluetoothMessageId::BLUETOOTH_MESSAGE_AUTHENTICATION_RESULT => {
            warn!(
                "{} <blue>real HU Bluetooth passthrough:</> dropping unexpected {:?} on synthetic channel <b>{:#04x}</>; unsupported because only already_paired=true passthrough is implemented",
                get_name(proxy_type),
                message_id,
                pkt.channel
            );
            Ok(Some(PacketAction::Drop))
        }
        BluetoothMessageId::BLUETOOTH_MESSAGE_PAIRING_RESPONSE => {
            warn!(
                "{} <blue>real HU Bluetooth passthrough:</> dropping unexpected BluetoothPairingResponse on synthetic channel <b>{:#04x}</>",
                get_name(proxy_type),
                pkt.channel
            );
            Ok(Some(PacketAction::Drop))
        }
    }
}
