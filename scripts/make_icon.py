"""Generate a geometric first-party app mark using only Python standard library."""
import struct, zlib
from pathlib import Path
size=1024
pixels=bytearray()
rects=[(260,300,650,390),(260,300,350,550),(260,490,650,580),(560,490,650,760),(260,680,650,770),(680,180,850,240),(790,180,850,350)]
for y in range(size):
    pixels.append(0)
    for x in range(size):
        ink=any(l<=x<r and t<=y<b for l,t,r,b in rects) or (640<=x<=810 and 240<=y<=410 and abs(x+y-1050)<38)
        pixels.extend((200,255,131) if ink else (20,44,37))
def chunk(k,d):return struct.pack('!I',len(d))+k+d+struct.pack('!I',zlib.crc32(k+d)&0xffffffff)
raw=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('!IIBBBBB',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(pixels,9))+chunk(b'IEND',b'')
path=Path(__file__).resolve().parents[1]/'ios/ScopePilot/Assets.xcassets/AppIcon.appiconset/AppIcon.png'
path.write_bytes(raw)
print(path)
