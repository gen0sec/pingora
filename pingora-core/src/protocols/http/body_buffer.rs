// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bytes::{Bytes, BytesMut};

/// A buffer with size limit. When the total amount of data written to the buffer is below the limit
/// all the data will be held in the buffer. Otherwise, the buffer will report to be truncated.
pub struct FixedBuffer {
    buffer: BytesMut,
    capacity: usize,
    truncated: bool,
}

impl FixedBuffer {
    pub fn new(capacity: usize) -> Self {
        FixedBuffer {
            buffer: BytesMut::new(),
            capacity,
            truncated: false,
        }
    }

    // TODO: maybe store a Vec of Bytes for zero-copy
    pub fn write_to_buffer(&mut self, data: &Bytes) {
        if self.truncated {
            return;
        }

        if self.buffer.len() + data.len() <= self.capacity {
            self.buffer.extend_from_slice(data);
        } else {
            // Buffered data is no longer usable for a retry, so release its allocation.
            self.buffer = BytesMut::new();
            self.truncated = true;
        }
    }

    pub fn clear(&mut self) {
        self.truncated = false;
        self.buffer.clear();
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.len() == 0
    }
    /// Raise (or lower) the capacity of a buffer that has not started filling.
    ///
    /// Only meaningful before any body byte has been written: once data is in,
    /// changing the ceiling cannot un-truncate what was already dropped, so
    /// this leaves a non-empty buffer alone and reports `false`.
    ///
    /// Exists so a caller that needs the whole body retained — a proxy holding
    /// a request back for content inspection, say — can widen the ceiling for
    /// the requests it cares about, instead of every deployment paying a larger
    /// default.
    pub fn set_capacity(&mut self, capacity: usize) -> bool {
        if !self.buffer.is_empty() || self.truncated {
            return false;
        }
        self.capacity = capacity;
        true
    }

    /// Raise the capacity of a buffer that may already hold data.
    ///
    /// Sound as long as nothing was dropped: bytes already in stay, and the
    /// ceiling only grows. A truncated buffer cannot be repaired, so it is
    /// left alone and this reports `false`. A `capacity` below the current
    /// one changes nothing and still reports `true`: the ceiling never lowers.
    ///
    /// Exists so a later stage of a proxy (content scanning, a per-route body
    /// cap) can grow the retry buffer that an earlier stage already started
    /// filling, where [`Self::set_capacity`] would refuse.
    pub fn raise_capacity(&mut self, capacity: usize) -> bool {
        if self.truncated {
            return false;
        }
        self.capacity = self.capacity.max(capacity);
        true
    }

    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
    pub fn get_buffer(&self) -> Option<Bytes> {
        // TODO: return None if truncated?
        if !self.is_empty() {
            Some(self.buffer.clone().freeze())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_storage_when_truncated() {
        let mut buffer = FixedBuffer::new(4);
        buffer.write_to_buffer(&Bytes::from_static(b"1234"));
        assert!(buffer.buffer.capacity() >= 4);

        buffer.write_to_buffer(&Bytes::from_static(b"5"));

        assert!(buffer.is_truncated());
        assert_eq!(buffer.buffer.capacity(), 0);
        assert!(buffer.get_buffer().is_none());
    }

    #[test]
    fn raised_capacity_retains_a_body_the_default_would_truncate() {
        let mut buf = FixedBuffer::new(4);
        assert!(buf.set_capacity(16));

        buf.write_to_buffer(&Bytes::from_static(b"0123456789"));
        assert!(!buf.is_truncated());
        assert_eq!(buf.get_buffer().unwrap(), Bytes::from_static(b"0123456789"));
    }

    /// Widening after bytes have landed cannot recover anything already
    /// dropped, so the change is refused rather than silently reporting a whole
    /// body that is actually a prefix.
    #[test]
    fn capacity_change_is_refused_once_the_buffer_has_data() {
        let mut buf = FixedBuffer::new(8);
        buf.write_to_buffer(&Bytes::from_static(b"abc"));
        assert!(!buf.set_capacity(1024));
    }

    #[test]
    fn capacity_change_is_refused_after_truncation() {
        let mut buf = FixedBuffer::new(2);
        buf.write_to_buffer(&Bytes::from_static(b"abcdef"));
        assert!(buf.is_truncated());
        assert!(!buf.set_capacity(1024));
        assert!(buf.is_truncated(), "still truncated after a refused resize");
    }

    #[test]
    fn raise_after_partial_fill_keeps_bytes_and_accepts_more() {
        let mut buf = FixedBuffer::new(4);
        buf.write_to_buffer(&Bytes::from_static(b"abc"));

        assert!(buf.raise_capacity(8));
        assert!(!buf.is_truncated());
        buf.write_to_buffer(&Bytes::from_static(b"defgh"));

        assert!(!buf.is_truncated());
        assert_eq!(buf.get_buffer().unwrap(), Bytes::from_static(b"abcdefgh"));

        buf.write_to_buffer(&Bytes::from_static(b"i"));
        assert!(buf.is_truncated(), "the new ceiling still applies");
    }

    #[test]
    fn raise_after_truncation_is_refused() {
        let mut buf = FixedBuffer::new(2);
        buf.write_to_buffer(&Bytes::from_static(b"abcdef"));
        assert!(buf.is_truncated());

        assert!(!buf.raise_capacity(1024));
        assert!(buf.is_truncated());
        buf.write_to_buffer(&Bytes::from_static(b"x"));
        assert!(buf.get_buffer().is_none());
    }

    #[test]
    fn raise_to_a_lower_value_keeps_the_capacity() {
        let mut buf = FixedBuffer::new(8);
        buf.write_to_buffer(&Bytes::from_static(b"abc"));

        assert!(buf.raise_capacity(2));
        buf.write_to_buffer(&Bytes::from_static(b"defgh"));
        assert!(!buf.is_truncated(), "capacity stayed at 8");
        assert_eq!(buf.get_buffer().unwrap(), Bytes::from_static(b"abcdefgh"));
    }

    #[test]
    fn raise_on_an_empty_buffer_works() {
        let mut buf = FixedBuffer::new(2);
        assert!(buf.raise_capacity(6));
        buf.write_to_buffer(&Bytes::from_static(b"abcdef"));
        assert!(!buf.is_truncated());
    }
}
