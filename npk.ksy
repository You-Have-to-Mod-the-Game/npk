# Credit: spotlightishere & MCMi460
meta:
  id: npk
  file-extension: npk
  endian: le
seq:
  - id: file_magic
    type: u4
  - id: file_length
    type: u4
  - id: unk1
    type: u1
  - id: file_count
    type: u2
  - id: unk2
    type: u1
  - id: file_data
    size: file_length - 12
  - id: file_entries
    type: file_entry
    repeat: expr
    repeat-expr: file_count
  
types:
  file_entry:
    seq:
      - id: file_name
        type: strz
        size: 248
        encoding: ascii
      - id: entry_start
        type: u4
      - id: entry_length
        type: u4
    instances:
      contents:
        pos: entry_start
        size: entry_length