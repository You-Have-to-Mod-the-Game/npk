# Reverse-engineering by spotlightishere & MCMi460
# Program by MCMi460
from pathlib import Path
from io import BytesIO
from argparse import ArgumentParser


class NPK:
    def __init__(self):
        self.file_magic = bytearray([0x6E, 0x70, 0x6B, 0x2E])
        self.unk1 = b"\x00"
        self.unk2 = b"\x00"

    def _fb(data: bytes) -> int:
        return int.from_bytes(data, byteorder="little")

    def _tb(data: int, size: int) -> bytes:
        return data.to_bytes(size, byteorder="little")

    def load(self, path: Path):
        with open(path, "rb") as file:
            npk = BytesIO(file.read())
        assert npk.read(4) == self.file_magic
        self.file_length = NPK._fb(npk.read(4))
        self.unk1 = npk.read(1)
        self.file_count = NPK._fb(npk.read(2))
        self.unk2 = npk.read(1)
        self.file_data = npk.read(self.file_length - 12)
        self.file_entries = [
            FileEntry(self.file_data, npk.read(256))
            for entry in range(0, self.file_count * 256, 256)
        ]

    def save(self, path: Path):
        with open(path, "wb") as file:
            file.write(self.file_magic)
            file.write(NPK._tb(self.file_length, 4))
            file.write(self.unk1)
            file.write(NPK._tb(self.file_count, 2))
            file.write(self.unk2)
            file.write(self.file_data)
            for entry in self.file_entries:
                file.write(entry.out())

    def output(self, path: Path):
        path.mkdir()
        for file in self.file_entries:
            with open(path / file.name, "wb") as desc:
                desc.write(file.contents)

    def input(self, path: Path):
        self.file_data = BytesIO()
        self.file_entries = []
        for file in path.iterdir():
            assert file.is_file()
            entry = FileEntry(None, None)
            entry.name = file.name
            with open(file, "rb") as desc:
                entry.contents = desc.read()
                entry.length = len(entry.contents)
                entry.start = self.file_data.tell() + 12
                self.file_data.write(entry.contents)
                self.file_entries.append(entry)
        self.file_data = self.file_data.getvalue()
        self.file_length = len(self.file_data) + 12
        self.file_count = len(self.file_entries)


class FileEntry:
    def __init__(self, file_data: bytes, entry: bytes):
        if file_data is not None and entry is not None:
            self.name = entry[:248].rstrip(b"\0").decode("ascii")
            self.start = NPK._fb(entry[248:252])
            self.length = NPK._fb(entry[252:])
            self.contents = file_data[self.start - 12 : self.start - 12 + self.length]
        else:
            self.name = None
            self.entry_start = None
            self.entry_length = None
            self.contents = None

    def out(self) -> bytes:
        name = self.name.encode("ascii")
        name += b"\0" * (248 - len(name))
        return name + NPK._tb(self.start, 4) + NPK._tb(self.length, 4)


def unpack_npk(path: pathlib.Path):
    assert path.is_file()
    obj = NPK()
    obj.load(path)
    obj.output(path.parent / path.stem)


def pack_npk(path: pathlib.Path):
    assert path.is_dir()
    obj = NPK()
    obj.input(path)
    obj.save(path.with_suffix(".npk"))


if __name__ == "__main__":
    parser = ArgumentParser(description="npk (un)packer")

    parser.add_argument("input", type=str, help="path to input (.npk/folder)")

    args = parser.parse_args()
    input_path = Path(args.input)

    if input_path.is_file():
        unpack_npk(input_path)
    elif input_path.is_dir():
        pack_npk(input_path)
    else:
        raise ValueError("invalid input specified: %s" % input_path)
