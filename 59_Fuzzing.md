# Fuzzing

## Overview
Fuzzing is a more targeted testing technique that follows spiking in the buffer overflow exploitation process. It involves sending malformed data to an application in a structured way to determine exactly what input causes a crash.

## Key Concepts

- **Purpose**: Send increasingly structured malformed data to identify precise crash conditions
- **Approach**: More systematic than spiking, focusing on specific functions
- **Goal**: Determine the approximate buffer size that causes a crash

## Process

1. **Target Selection**: Focus on the vulnerable functions identified during spiking
2. **Payload Creation**: Create a script to send incremental buffer sizes to the target
3. **Execution**: Send increasingly large strings until the application crashes
4. **Analysis**: Determine the approximate buffer size that causes the crash
5. **Documentation**: Record the buffer size for further exploitation

## Python Fuzzing Script Example

```python
#!/usr/bin/python
import socket, sys

buffer = ["A"]
counter = 100
while len(buffer) <= 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    print(f"Fuzzing with {len(string)} bytes")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect(('TARGET_IP', TARGET_PORT))
    s.send(('COMMAND ' + string + '\r\n').encode())
    s.close()
```

## Important Considerations

- Start with small buffer sizes and gradually increase
- Monitor the target application for crashes
- Record exact buffer size that causes crashes
- The target application will need to be restarted after each crash
- Focus on consistent reproducibility

## Differences from Spiking

- **Spiking**: Identifies which function might be vulnerable
- **Fuzzing**: Determines how much data is needed to crash the function

## Next Steps After Successful Fuzzing

After determining the approximate crash point through fuzzing:
1. Find the exact offset that overwrites the EIP
2. Control the EIP value
3. Identify bad characters
4. Find a usable module
5. Generate appropriate shellcode
