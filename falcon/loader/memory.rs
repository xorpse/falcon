use std::collections::BTreeMap;
use std::cmp::{Ord, Ordering, PartialOrd};

bitflags! {
    pub flags MemoryPermissions: u32 {
        const NONE    = 0b00000000,
        const READ    = 0b00000001,
        const WRITE   = 0b00000010,
        const EXECUTE = 0b00000100
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySegment {
    address: u64,
    bytes: Vec<u8>,
    permissions: MemoryPermissions
}

impl MemorySegment {
    pub fn new(address: u64, bytes: Vec<u8>, permissions: MemoryPermissions)
    -> MemorySegment {
        MemorySegment {
            address: address,
            bytes: bytes,
            permissions: permissions
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn permissions(&self) -> MemoryPermissions {
        self.permissions
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    fn truncate(&mut self, new_size: usize) {
        self.bytes.truncate(new_size)
    }
}

impl Ord for MemorySegment {
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

impl PartialOrd for MemorySegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


#[derive(Clone, Debug)]
pub struct Memory {
    segments: BTreeMap<u64, MemorySegment>
}

impl Memory {
    /// Create a new, empty `Memory`
    pub fn new() -> Memory {
        Memory {
            segments: BTreeMap::new()
        }
    }

    /// Add a `MemorySegment` to this `Memory`
    ///
    /// Does handle overlapping memory segments, placing this segment,
    /// "On top of," any existing segments.
    pub fn add_segment(&mut self, segment: MemorySegment) {
        // handle overlapping segments
        let mut add_segments = Vec::new();
        let mut del_segments = Vec::new();
        for ref mut s in self.segments.iter_mut() {
            let address = s.0;
            let ref mut s = s.1;
            // if a segment runs into this one, truncate it
            if s.address() + s.len() as u64 > segment.address() {
                s.truncate((segment.address() - *address) as usize);
            }
            // if a segment starts in this one, adjust it
            if    s.address() > segment.address()
               && s.address() < segment.address() + segment.len() as u64 {
                if s.address() + s.len() as u64 > segment.address() + segment.len() as u64 {
                    let offset = (  segment.address() 
                                  + segment.len() as u64
                                  - s.address()) as usize;
                    let new_segment = MemorySegment::new(
                        segment.address() + segment.len() as u64,
                        s.bytes().get(offset..s.len()).unwrap().to_vec(),
                        s.permissions()
                    );
                    add_segments.push(new_segment);
                }
                del_segments.push(s.address());
           }
        }

        for address in del_segments {
            self.segments.remove(&address);
        }

        for segment in add_segments {
            self.segments.insert(segment.address(), segment);
        }

        self.segments.insert(segment.address(), segment);
    }
}