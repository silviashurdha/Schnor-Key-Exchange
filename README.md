Schnorr Signature Implementation
Overview

This project implements a simplified version of the Schnorr signature algorithm using elliptic curve cryptography (ECC) with the OpenSSL library. The code demonstrates key generation, signing, and signature verification processes.
Files

    main.c: Contains the main code implementing key generation, signing, and signature verification.
    functions.c: Includes helper functions for reading from and writing to files, converting data to hexadecimal format, and displaying data in hexadecimal.
    functions.h: Header file declaring function prototypes and including necessary library headers.
    Message.txt: Contains the message that will be signed.
    Seed.txt: Contains a seed used for private key generation.
    PK_HEX.txt: Contains Alice's public key in hexadecimal format.
    R_Hex.txt: Contains the R component of Alice's signature in hexadecimal format.
    s_Hex.txt: Contains the s component of Alice's signature in hexadecimal format.
    Verification_Result.txt: Output file that stores the result of signature verification.

How to Use

    Compilation:
        Compile the program using a C compiler, e.g., gcc main.c functions.c -o schnorr -lssl -lcrypto.

    Execution:
        Run the compiled program with command-line arguments:

        bash

        ./schnorr Message.txt PK_HEX.txt R_Hex.txt s_Hex.txt

        Replace Message.txt, PK_HEX.txt, R_Hex.txt, and s_Hex.txt with actual file names containing appropriate data.

    Output:
        After execution, the program will output the result of signature verification to Verification_Result.txt.

Dependencies

    OpenSSL library (libssl and libcrypto)
