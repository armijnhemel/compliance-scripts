meta:
  id: mz
  file-extension: mz
  endian: le
seq:
  - id: entry
    type: entry
    repeat: eos
types:
  entry:
    seq:
      - id: md5
        size: 14
      - id: len_compressed
        type: u4
      - id: data
        size: len_compressed
        process: zlib
