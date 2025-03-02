# Spiking

## Overview
Spiking is a basic reconnaissance technique used in buffer overflow exploitation to identify which parts of an application might be vulnerable to buffer overflows. It helps pinpoint where to focus further testing.

## Key Concepts

- **Purpose**: Identify vulnerable functions or parameters in an application
- **Tools**: Generic spike scripts (`.spk` files)
- **Approach**: Send increasingly large amounts of data to different parts of the application

## Process

1. **Target Identification**: Identify the target application and its potential inputs
2. **Create Spike Script**: Write a simple spike script to test a specific function
3. **Execution**: Run the script against the target function
4. **Observation**: Watch for crashes or unexpected behavior
5. **Documentation**: Note which functions crash and under what conditions

## Sample Spike Script Structure

```
s_readline(); // Read a line from the server
s_string("COMMAND "); // Replace COMMAND with the actual command you're testing
s_string_variable("0"); // Variable section that will be fuzzed
```

## Important Considerations

- Spiking is just the first step in buffer overflow analysis
- A crash during spiking indicates a potential vulnerability, but further analysis is required
- Not all crashes indicate exploitable buffer overflows
- Document all findings for further fuzzing

## Applications

- Used primarily on network services and protocols
- Particularly useful for applications that accept various commands
- Can be applied to network services like FTP, SMTP, HTTP, etc.

## Next Steps After Successful Spike

After identifying a vulnerable function through spiking, the next steps are:
1. Fuzzing (sending more structured data)
2. Finding the exact offset that causes the crash
3. Overwriting the EIP
4. Identifying bad characters
5. Finding a usable module
6. Generating shellcode
