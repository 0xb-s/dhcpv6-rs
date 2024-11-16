use std::collections::HashMap;
use std::net::Ipv6Addr;

/// a DHCPv6 client
#[derive(Debug, Clone)]
pub struct Dhcpv6Client {
    pub id: String,
    pub link_local_address: Ipv6Addr,
}

/// an IPv6 prefix allocated to a client
#[derive(Debug, Clone)]
pub struct Ipv6Prefix {
    pub base_address: Ipv6Addr,
    pub prefix_length: u8,
}

/// Manages the DHCPv6 server
pub struct Dhcpv6Server {
    pub pool_start: Ipv6Addr,
    pub pool_size: u32,
    pub prefix_length: u8,
    pub allocated_prefixes: HashMap<String, Ipv6Prefix>,
}
impl Dhcpv6Server {
    /// Create a new DHCPv6 server
    pub fn new(pool_start: Ipv6Addr, pool_size: u32, prefix_length: u8) -> Self {
        Self {
            pool_start,
            pool_size,
            prefix_length,
            allocated_prefixes: HashMap::new(),
        }
    }

    pub fn allocate_prefix(&mut self, client_id: &str) -> Option<Ipv6Prefix> {
        if let Some(prefix) = self.allocated_prefixes.get(client_id) {
            return Some(prefix.clone());
        }

        let offset = self.allocated_prefixes.len() as u32;
        if offset >= self.pool_size {
            return None; // no available prefixes
        }

        let base_address = Self::calculate_next_prefix(self.pool_start, offset, self.prefix_length);
        let prefix = Ipv6Prefix {
            base_address,
            prefix_length: self.prefix_length,
        };
        self.allocated_prefixes
            .insert(client_id.to_string(), prefix.clone());
        Some(prefix)
    }

    fn calculate_next_prefix(pool_start: Ipv6Addr, offset: u32, prefix_lenght: u8) -> Ipv6Addr {
        let mut octets = pool_start.octets();
        // increment here is used to calculate how much to increment the base of ipv6 addr
        // to generate the next prefix in pool

        // 128- prefix_lenght will calculate the number of bits of the address that are not part of the fixed prefix
        // and then it used to be shifted with the offset
        let increment = offset << (128 - prefix_lenght) as u32;

        for i in (0..16).rev() {
            let (sum, overflow) = octets[i].overflowing_add((increment >> (i * 8)) as u8);

            octets[i] = sum;

            if !overflow {
                break;
            }
        }
        Ipv6Addr::from(octets)
    }

    pub fn release_prefix(&mut self, client_id: &str) {
        self.allocated_prefixes.remove(client_id);
    }
}

// TODO custom error
pub fn parse_dhcp_message(data: &[u8]) -> Option<String> {
    if data.len() == 4 {
        return None;
    }

    let message_type = data[0];
    if message_type != 1 {
        return None;
    }

    let mut offset = 4;

    while offset + 4 <= data.len() {
        let option_code = u16::from_be_bytes([data[offset], data[offset + 1]]);

        let option_lenght = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        offset += 4;

        if offset + option_lenght > data.len() {
            break;
        }
        if option_code == 1 {
            return Some(
                data[offset..offset + option_lenght]
                    .iter()
                    .map(|byte| format!("{:02x}", byte))
                    .collect::<String>(),
            );
        }

        offset += option_lenght;
    }

    None
}

// todo
pub fn construct_dhcp_reply(client_id: &str, prefix: &Ipv6Prefix) -> Vec<u8> {
    let mut reply = Vec::new();
    reply.push(7);

    reply.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    //client
    reply.extend_from_slice(&[0x00, 0x01]);
    let client_id_bytes = hex::decode(client_id).unwrap_or_default();
    reply.extend_from_slice(&(client_id_bytes.len() as u16).to_be_bytes());
    reply.extend_from_slice(&client_id_bytes);
    // Prefix
    reply.extend_from_slice(&[0x00, 0x19]);
    reply.extend_from_slice(&((4 + 16) as u16).to_be_bytes());

    reply.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    reply.extend_from_slice(&prefix.base_address.octets());
    reply.push(prefix.prefix_length);
    reply.extend_from_slice(&[0x00, 0x00]);

    reply
}
