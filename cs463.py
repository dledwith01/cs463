#FILENAME: cs463.py
#STUDENT NAME: DANIEL LEDWITH
#STUDENT UIN: 01265466
#DATE: 11/28/2023

#For more information, refer to cs463_project.txt
#For a sample run, refer to sample_run.pdf

###IMPORT
#import system from os to handle clear screen function
from os import system, name

###FUNCTION DEFINITIONS###
#USER INTERFACE FUNCTIONS
#Define function to clear screen depending on os
def clear_screen():
    if name == 'nt':
        system('cls')
    else:
        system('clear')

#Define function to print decorative banner
def print_banner():
    print("*"*51 + "\n" + "*"*51)
    print("*"*14 + " "*5 + "CS463 PROJECT" + " "*5 + "*"*14)
    print("*"*14 + " "*3 + "BY DANIEL LEDWITH" + " "*3 + "*"*14)
    print("*"*14 + " "*7 + "FALL 2023" + " "*7 + "*"*14)
    print("*"*51 + "\n" + "*"*51 + "\n")

#Define function to run main menu
def main_menu():
    #Clear screen and print decorative banner
    clear_screen()
    print_banner()

    #Prompt the user to enter a message to be encrypted
    #Collect and store message in a string variable called plaintext
    plaintext = input("Enter a short message to be encrypted (1 line): ")

    #Input validation to disallow a null message
    if(plaintext == ''):
        print("\nNo message to encrypt!")
        return
    
    #Input validation to disallow non-ASCII characters
    for x in plaintext:
        if(ord(x) > 126 or ord(x) < 32):
            print("\nUnacceptable character(s) detected. Please try another message. For more information on acceptable characters, refer to cs463_project.txt")
            return

    #Clear screen and print decorative banner
    #Confirm message to be encrypted
    clear_screen()
    print_banner()
    print("plaintext: " + plaintext + "\n")

    #Prompt user to select an encryption method from a list
    print("Encryption Methods")
    print("1. Caesar Cipher")
    print("2. Affine Cipher")
    print("3. Linear Feedback Shift Register")
    print("4. DES")
    print("5. RSA")
    print("6. Elgamal")
    encryption_method = input("\nEnter an encryption method from list above (1 - 6): ")

    #Route plaintext to selected encryption method
    match encryption_method:
        case "1": encrypt_caesar(plaintext)
        case "2": encrypt_affine(plaintext)
        case "3": encrypt_lfsr(plaintext)
        case "4": des_blocks(plaintext)
        case "5": rsa_blocks(plaintext)
        case "6": elgamal_blocks(plaintext)
        case _: print("\nInvalid selection")

#COMPUTATIONAL FUNCTIONS
#Define function to convert decimal to binary
def decimal_to_binary(decimal):
    return format(decimal, "#010b").replace("0b", "")

#Define function to shift bits left n number of positions
def shift(k, n):
    s = ""
    for x in range(n):
        for y in range(1, len(k)):
            s += k[y]
        s += k[0]
        k = s
        s = ""
    return k

#ENCCRYPTION/DECRYPTION FUNCTIONS
#CAESAR CIPHER
#Define function to encrypt with Caesar cipher
def encrypt_caesar(plaintext):
    clear_screen()
    print_banner()
    print("Encryption Using Caesar Cipher:")

    #Convert plaintext string to ASCII array
    plaintext_ASCII = []
    for x in plaintext:
        plaintext_ASCII.append(ord(x))

    #Declare key to be used
    k = 29

    #Perform encryption using key
    ciphertext_ASCII = []
    for x in plaintext_ASCII:
        ciphertext_ASCII.append((x - 32 + k) % 95 + 32)

    #Convert ASCII array to string
    ciphertext = ""
    for x in ciphertext_ASCII:
        ciphertext += chr(x)

    #Print plaintext and ciphertext to console
    print("\nplaintext:  " + plaintext)
    print("ciphertext: " + ciphertext)

    #Call function to decrypt ciphertext
    decrypt_caesar(ciphertext)

#Define function to decrypt Caesar cipher
def decrypt_caesar(ciphertext):
    print("\nDecryption Using Caesar Cipher:")

    #Convert ciphertext string to ASCII array
    ciphertext_ASCII = []
    for x in ciphertext:
        ciphertext_ASCII.append(ord(x))

    #Declare key to be used
    k = 29

    #Perform decryption using key
    plaintext_ASCII = []
    for x in ciphertext_ASCII:
        plaintext_ASCII.append((x - 32 - k) % 95 + 32)

    #Convert ASCII array to string
    plaintext = ""
    for x in plaintext_ASCII:
        plaintext += chr(x)

    #Print ciphertext and plaintext to console
    print("\nciphertext: " + ciphertext)
    print("plaintext:  " + plaintext)

#AFFINE CIPHER
#Define function to encrypt with affine cipher
def encrypt_affine(plaintext):
    clear_screen()
    print_banner()
    print("Encryption Using Affine Cipher:")

    #Convert plaintext string to ASCII array
    plaintext_ASCII = []
    for x in plaintext:
        plaintext_ASCII.append(ord(x))

    #Declare keys to be used
    a = 7
    b = 29

    #Perform encryption using keys
    ciphertext_ASCII = []
    for x in plaintext_ASCII:
        ciphertext_ASCII.append(((x - 32) * a + b) % 95 + 32)

    #Convert ASCII array to string
    ciphertext = ""
    for x in ciphertext_ASCII:
        ciphertext += chr(x)

    #Print plaintext and ciphertext to console
    print("\nplaintext:  " + plaintext)
    print("ciphertext: " + ciphertext)

    #Call func5tino to decrypt ciphertext
    decrypt_affine(ciphertext)

#Define function to decrypt affine cipher
def decrypt_affine(ciphertext):
    print("\nDecryption Using Affine Cipher:")

    #Convert ciphertext string to ASCII array
    ciphertext_ASCII = []
    for x in ciphertext:
        ciphertext_ASCII.append(ord(x))

    #Declare keys to be used
    a = 7
    b = 29

    #Compute modular multiplicative inverse of a
    a_inverse = pow(a, -1, 95)

    #Perform decryption using keys
    plaintext_ASCII = []
    for x in ciphertext_ASCII:
        plaintext_ASCII.append((x - 32 - b) * a_inverse % 95 + 32)

    #Convert ASCII array to string
    plaintext = ""
    for x in plaintext_ASCII:
        plaintext += chr(x)

    #Print ciphertext and plaintext to console
    print("\nciphertext: " + ciphertext)
    print("plaintext:  " + plaintext)

#LINEAR-FEEDBACK SHIFT REGISTER
#Define function to encrypt with linear-feedback shift register (LFSR)
def encrypt_lfsr(plaintext):
    clear_screen()
    print_banner()
    print("Encryption Using Linear-Feedback Shift Register:")

    #Declare variables
    ciphertext = ""
    init_seed = [0, 0, 1, 1, 0]
    seed = init_seed
    key_stream = ""

    #Convert plaintext to bits
    plaintext_binary = ""
    for x in plaintext:
        plaintext_binary += decimal_to_binary(ord(x))

    #Generate a key stream with length equal to length of plaintext bit stream
    key_stream += str(init_seed[4])
    temp_s = [0, 0, 0, 0, 0]
    while(len(key_stream) < len(plaintext_binary)):
        #Copy seed array to tmeporary array
        count = 0
        for x in seed:
            temp_s[count] = x
            count = count + 1

    	#Compute nested XOR output
        nested_xor = (seed[1] ^ (seed[2] ^ seed[3]))

        #Shift bits
        seed[0] = nested_xor
        seed[1] = temp_s[0]
        seed[2] = temp_s[1]
        seed[3] = temp_s[2]
        seed[4] = temp_s[3]
        
        #Append seed[4] to key stream
        key_stream += str(seed[4])

    #Convert plaintext bit stream and key stream to integers
    plaintext_integer = int(plaintext_binary, 2)
    key_stream_integer = int(key_stream, 2)

    #XOR plaintext integer and key stream integer
    ciphertext_integer = plaintext_integer ^ key_stream_integer

    #Convert ciphertext integer to bits, pad with 0's if length is less than key stream
    ciphertext_binary = decimal_to_binary(ciphertext_integer)
    ciphertext = ciphertext_binary.rjust(len(key_stream), "0")

    #Print plaintext and ciphertext to screen
    print("\nplaintext:  " + plaintext)
    print("ciphertext: " + ciphertext)
    
    #Call function to decrypt linear-feedback shift register
    decrypt_lfsr(ciphertext)

#Define function to decrypt linear-feedback shift register
def decrypt_lfsr(ciphertext):
    #Print message to screen
    print("\nDecryption Using Linear-Feedback Shift Register:")

    #Declare variables
    plaintext = ""
    init_seed = [0, 0, 1, 1, 0]
    seed = init_seed
    key_stream = ""

    #Generate a key stream with length equal to length of ciphertext bit stream
    key_stream += str(init_seed[4])
    temp_s = [0, 0, 0, 0, 0]
    while(len(key_stream) < len(ciphertext)):
        #Copy seed array to tmeporary array
        count = 0
        for x in seed:
            temp_s[count] = x
            count = count + 1

    	#Compute nested XOR output
        nested_xor = (seed[1] ^ (seed[2] ^ seed[3]))

        #Shift bits
        seed[0] = nested_xor
        seed[1] = temp_s[0]
        seed[2] = temp_s[1]
        seed[3] = temp_s[2]
        seed[4] = temp_s[3]
        
        #Append seed[4] to key stream
        key_stream += str(seed[4])

    #Convert ciphertext bit stream and key stream to integers
    ciphertext_integer = int(ciphertext, 2)
    key_stream_integer = int(key_stream, 2)

    #XOR ciphertext integer and key stream integer
    plaintext_integer = ciphertext_integer ^ key_stream_integer

    #Convert plaintext integer to bits, pad with 0's if length is less than key stream
    plaintext_binary = decimal_to_binary(plaintext_integer)
    plaintext_binary = plaintext_binary.rjust(len(key_stream), "0")

    #Decode plaintext bits to ASCII characters
    plaintext_binary_temp = plaintext_binary
    plaintext = ""
    while(plaintext_binary_temp):
        plaintext += chr(int(plaintext_binary_temp[:8], 2))
        plaintext_binary_temp = plaintext_binary_temp[8:]

    #Print ciphertext and plaintext to console
    print("\nciphertext: " + ciphertext)
    print("plaintext:  " + plaintext)

#DES
#Define function to split plaintext into 64-bit blocks to be encrypted and decrypted one at a time
def des_blocks(plaintext):
    clear_screen()
    print_banner()
    print("Encryption Using DES:")

    #Convert plaintext to bits
    plaintext_binary = ""
    for x in plaintext:
        plaintext_binary += decimal_to_binary(ord(x))
    
    #Store each 64-bit block in an array
    plaintext_binary_temp = plaintext_binary
    plaintext_binary_blocks = []
    while(plaintext_binary_temp):
        plaintext_binary_blocks.append(plaintext_binary_temp[:64])
        plaintext_binary_temp = plaintext_binary_temp[64:]
    
    #Encrypt each block
    ciphertext_blocks = []
    for x in plaintext_binary_blocks:
        ciphertext_blocks.append(encrypt_des(x))
    
    #Convert ciphertext array to bit stream
    ciphertext = ""
    for x in ciphertext_blocks:
        ciphertext += x
    
    #Print plaintext and ciphertext to screen
    print("\nplaintext: ", plaintext)
    print("ciphertext:", ciphertext)

    print("\nDecryption Using DES:")

    #Decrypt each ciphertext block
    plaintext_binary_blocks = []
    for x in ciphertext_blocks:
        plaintext_binary_blocks.append(decrypt_des(x))

    #Convert plaintext block to string
    plaintext = ""
    for x in plaintext_binary_blocks:
        plaintext += x

    #Print plaintext and ciphertext to screen
    print("\nciphertext:", ciphertext)
    print("plaintext: ", plaintext)
    
#Define function to encrypt with DES
def encrypt_des(plaintext):

    #Tables to be used
    table_pc_1 = [57, 49, 41, 33, 25, 17, 9, 
                  1, 58, 50, 42, 34, 26, 18, 
                  10, 2, 59, 51, 43, 35, 27, 
                  19, 11, 3, 60, 52, 44, 36, 
                  63, 55, 47, 39, 31, 23, 15, 
                  7, 62, 54, 46, 38, 30, 22, 
                  14, 6, 61, 53, 45, 37, 29, 
                  21, 13, 5, 28, 20, 12, 4]
    
    table_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 
                    1, 2, 2, 2, 2, 2, 2, 1]
    
    table_pc_2 = [14, 17, 11, 24, 1, 5, 
                  3, 28, 15, 6, 21, 10, 
                  23, 19, 12, 4, 26, 8,
                  16, 7, 27, 20, 13, 2,
                  41, 52, 31, 37, 47, 55,
                  30, 40, 51, 45, 33, 48,
                  44, 49, 39, 56, 34, 53,
                  46, 42, 50, 36, 29, 32]
    
    table_IP = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
    
    table_E = [32, 1, 2, 3, 4, 5,
               4, 5, 6, 7, 8, 9,
               8, 9, 10, 11, 12, 13,
               12, 13, 14, 15, 16, 17,
               16, 17, 18, 19, 20, 21,
               20, 21, 22, 23, 24, 25,
               24, 25, 26, 27, 28, 29,
               28, 29, 30, 31, 32, 1]
    
    table_s_box_1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
    
    table_s_box_2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]
    
    table_s_box_3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]
    
    table_s_box_4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

    table_s_box_5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0 ,14],
                     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

    table_s_box_6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

    table_s_box_7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2 ,15, 8, 6],
                     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 4, 2, 3, 12]]

    table_s_box_8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10 ,9, 3, 14, 5, 0, 12, 7],
                     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    
    table_P = [16, 7, 20, 21,
               29 ,12, 28, 17,
               1, 15, 23, 26,
               5, 18, 31, 10,
               2, 8, 24, 14,
               32, 27, 3, 9,
               19, 13, 30, 6,
               22, 11, 4, 25]
    
    table_IP_inverse = [40, 8, 48, 16, 56, 24, 64, 32,
                        39, 7, 47, 15, 55, 23, 63, 31,
                        38, 6, 46, 14, 54, 22, 62, 30,
                        37, 5, 45, 13, 53, 21, 61, 29,
                        36, 4, 44, 12, 52, 20, 60, 28,
                        35, 3, 43, 11, 51, 19, 59, 27,
                        34, 2, 42, 10, 50, 18, 58, 26,
                        33, 1, 41, 9, 49, 17, 57, 25]

    #Declare 64-bit key to be used
    k = 1383827165325090801

    #Convert key to bits
    k_binary = str(decimal_to_binary(k))

    #Pad with 0's if necessary (need 64 bits)
    if(len(k_binary) < 64):
        k_binary = k_binary.rjust(64, '0')

    #Permute 64-bit key acoording to table PC-1
    k_pc_1 = ""
    for x in range(56):
        k_pc_1 += k_binary[table_pc_1[x] - 1]
    
    #Split permuted key in half, store each half as left key and right key
    lk = k_pc_1[:28]
    rk = k_pc_1[28:]

    #Create 16 sub-keys using shift table
    LK = [lk]
    RK = [rk]
    
    for x in range(16):
        LK.append(shift(LK[x], table_shifts[x]))
        RK.append(shift(RK[x], table_shifts[x]))
    del(LK[0])
    del(RK[0])

    #Concatenate each left and right key pair
    K = []
    for x in range(16):
        K.append(LK[x] + RK[x])

    #Permute each key according to table PC-2
    K_PC_2 = [None] * 16
    p = ""
    for x in range(16):
        pair = K[x]
        for y in range(48):
            p += pair[table_pc_2[y] - 1]
        K_PC_2[x] = p
        p = ""

    #Begin message encryption
    plaintext_binary = plaintext

    #Pad with 0's if necessary
    if(len(plaintext_binary) < 64):
        plaintext_binary = plaintext_binary.rjust(64, '0')

    #Permute plaintext bits according to table IP
    plaintext_binary_IP = ""
    for x in range(64):
        plaintext_binary_IP += plaintext_binary[table_IP[x] - 1]

    #Split permuted message into left block and right block
    lb = plaintext_binary_IP[:32]
    rb = plaintext_binary_IP[32:]

    #Define f-function
    def f(r_n_minus_1_integer, k_n):
        #Convert r_n_minus_1 to bits, padding with 0's if necessary
        r_n_minus_1 = decimal_to_binary(r_n_minus_1_integer)
        if(len(r_n_minus_1) < 32):
            r_n_minus_1 = r_n_minus_1.rjust(32, "0") 

        #Expand r_n_minus_1 according to expansion table E (32 to 48 bits)
        r_n_minus_1_E = ""
        for x in range(48):
            r_n_minus_1_E += r_n_minus_1[table_E[x] - 1]
        
        #Convert expanded r_n_minus1 and key to integers to facilitate XOR
        r_n_minus_1_E_integer = int(r_n_minus_1_E, 2)
        k_n_integer = int(k_n, 2)
        
        #XOR expanded r_n_minus_1 with key
        xor_output_integer = r_n_minus_1_E_integer ^ k_n_integer

        #Convert XOR output integer to bits, pad with 0's if necessary
        xor_output = decimal_to_binary(xor_output_integer)

        if(len(xor_output) < 48):
            xor_output = xor_output.rjust(48, "0")

        #Split XOR output into 8 6-bit blocks
        xor_output_temp = xor_output
        xor_output_blocks = []
        while(xor_output_temp):
            xor_output_blocks.append(xor_output_temp[:6])
            xor_output_temp = xor_output_temp[6:]

        #Find substitution box rows and columns from each 6-bit block
        rows = []
        columns = []
        for x in xor_output_blocks:
            rows.append(int((str(x[0]) + str(x[5])), 2))
            columns.append(int((str(x[1]) + str(x[2]) + str(x[3]) + str(x[4])), 2))

        #Use substitution boxes
        s_box_output = ""
        s_box_output += decimal_to_binary(table_s_box_1[rows[0]][columns[0]])[4:]
        s_box_output += decimal_to_binary(table_s_box_2[rows[1]][columns[1]])[4:]
        s_box_output += decimal_to_binary(table_s_box_3[rows[2]][columns[2]])[4:]
        s_box_output += decimal_to_binary(table_s_box_4[rows[3]][columns[3]])[4:]
        s_box_output += decimal_to_binary(table_s_box_5[rows[4]][columns[4]])[4:]
        s_box_output += decimal_to_binary(table_s_box_6[rows[5]][columns[5]])[4:]
        s_box_output += decimal_to_binary(table_s_box_7[rows[6]][columns[6]])[4:]
        s_box_output += decimal_to_binary(table_s_box_8[rows[7]][columns[7]])[4:]

        #Permute substitution box output according to table P
        s_box_output_P = ""
        for x in range(32):
            s_box_output_P += s_box_output[table_P[x] - 1]

        #Return permuted substitution box output as integer
        return int(s_box_output_P, 2)

    #Convert lb and rb to integers
    lb0_integer = int(lb, 2)
    rb0_integer = int(rb, 2)

    #set lb1 equal to rb0 and rb 1 equal to XOR lb0 with f-function output
    lb1_integer = rb0_integer
    rb1_integer = lb0_integer ^ f(rb0_integer, K_PC_2[0])
    
    #Do this for all 15 rounds
    lb2_integer = rb1_integer
    rb2_integer = lb1_integer ^ f(rb1_integer, K_PC_2[1])
    lb3_integer = rb2_integer
    rb3_integer = lb2_integer ^ f(rb2_integer, K_PC_2[2])
    lb4_integer = rb3_integer
    rb4_integer = lb3_integer ^ f(rb3_integer, K_PC_2[3])
    lb5_integer = rb4_integer
    rb5_integer = lb4_integer ^ f(rb4_integer, K_PC_2[4])
    lb6_integer = rb5_integer
    rb6_integer = lb5_integer ^ f(rb5_integer, K_PC_2[5])
    lb7_integer = rb6_integer
    rb7_integer = lb6_integer ^ f(rb6_integer, K_PC_2[6])
    lb8_integer = rb7_integer
    rb8_integer = lb7_integer ^ f(rb7_integer, K_PC_2[7])
    lb9_integer = rb8_integer
    rb9_integer = lb8_integer ^ f(rb8_integer, K_PC_2[8])
    lb10_integer = rb9_integer
    rb10_integer = lb9_integer ^ f(rb9_integer, K_PC_2[9])
    lb11_integer = rb10_integer
    rb11_integer = lb10_integer ^ f(rb10_integer, K_PC_2[10])
    lb12_integer = rb11_integer
    rb12_integer = lb11_integer ^ f(rb11_integer, K_PC_2[11])
    lb13_integer = rb12_integer
    rb13_integer = lb12_integer ^ f(rb12_integer, K_PC_2[12])
    lb14_integer = rb13_integer
    rb14_integer = lb13_integer ^ f(rb13_integer, K_PC_2[13])
    lb15_integer = rb14_integer
    rb15_integer = lb14_integer ^ f(rb14_integer, K_PC_2[14])
    lb16_integer = rb15_integer
    rb16_integer = lb15_integer ^ f(rb15_integer, K_PC_2[15])

    #Convert lb16 and rb16 to bits and pad with 0's if necessary
    lb16 = decimal_to_binary(lb16_integer)
    if(len(lb16) < 32):
        lb16 = lb16.rjust(32, "0")
    rb16 = decimal_to_binary(rb16_integer)
    if(len(rb16) < 32):
        rb16 = rb16.rjust(32, "0")

    #Reverse the order of concatenated block
    rb16lb16 = rb16 + lb16

    #Permute reversed concatenated block according to IP inverse table
    ciphertext = ""
    for x in range(64):
        ciphertext += rb16lb16[table_IP_inverse[x] - 1]

    #Return ciphertext
    return ciphertext

#Define function to decrypt DES
def decrypt_des(ciphertext):
    #Tables to be used
    table_pc_1 = [57, 49, 41, 33, 25, 17, 9, 
                  1, 58, 50, 42, 34, 26, 18, 
                  10, 2, 59, 51, 43, 35, 27, 
                  19, 11, 3, 60, 52, 44, 36, 
                  63, 55, 47, 39, 31, 23, 15, 
                  7, 62, 54, 46, 38, 30, 22, 
                  14, 6, 61, 53, 45, 37, 29, 
                  21, 13, 5, 28, 20, 12, 4]
    
    table_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 
                    1, 2, 2, 2, 2, 2, 2, 1]
    
    table_pc_2 = [14, 17, 11, 24, 1, 5, 
                  3, 28, 15, 6, 21, 10, 
                  23, 19, 12, 4, 26, 8,
                  16, 7, 27, 20, 13, 2,
                  41, 52, 31, 37, 47, 55,
                  30, 40, 51, 45, 33, 48,
                  44, 49, 39, 56, 34, 53,
                  46, 42, 50, 36, 29, 32]
    
    table_IP = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
    
    table_E = [32, 1, 2, 3, 4, 5,
               4, 5, 6, 7, 8, 9,
               8, 9, 10, 11, 12, 13,
               12, 13, 14, 15, 16, 17,
               16, 17, 18, 19, 20, 21,
               20, 21, 22, 23, 24, 25,
               24, 25, 26, 27, 28, 29,
               28, 29, 30, 31, 32, 1]
    
    table_s_box_1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
    
    table_s_box_2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]
    
    table_s_box_3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]
    
    table_s_box_4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

    table_s_box_5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0 ,14],
                     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

    table_s_box_6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

    table_s_box_7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2 ,15, 8, 6],
                     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 4, 2, 3, 12]]

    table_s_box_8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10 ,9, 3, 14, 5, 0, 12, 7],
                     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
                     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    
    table_P = [16, 7, 20, 21,
               29 ,12, 28, 17,
               1, 15, 23, 26,
               5, 18, 31, 10,
               2, 8, 24, 14,
               32, 27, 3, 9,
               19, 13, 30, 6,
               22, 11, 4, 25]
    
    table_IP_inverse = [40, 8, 48, 16, 56, 24, 64, 32,
                        39, 7, 47, 15, 55, 23, 63, 31,
                        38, 6, 46, 14, 54, 22, 62, 30,
                        37, 5, 45, 13, 53, 21, 61, 29,
                        36, 4, 44, 12, 52, 20, 60, 28,
                        35, 3, 43, 11, 51, 19, 59, 27,
                        34, 2, 42, 10, 50, 18, 58, 26,
                        33, 1, 41, 9, 49, 17, 57, 25]

    #Declare 64-bit key to be used
    k = 1383827165325090801

    #Convert key to bits
    k_binary = str(decimal_to_binary(k))

    #Pad with 0's if necessary (need 64 bits)
    if(len(k_binary) < 64):
        k_binary = k_binary.rjust(64, '0')

    #Permute 64-bit key acoording to table PC-1
    k_pc_1 = ""
    for x in range(56):
        k_pc_1 += k_binary[table_pc_1[x] - 1]
    
    #Split permuted key in half, store each half as left key and right key
    lk = k_pc_1[:28]
    rk = k_pc_1[28:]

    #Create 16 sub-keys using shift table
    LK = [lk]
    RK = [rk]
    
    for x in range(16):
        LK.append(shift(LK[x], table_shifts[x]))
        RK.append(shift(RK[x], table_shifts[x]))
    del(LK[0])
    del(RK[0])

    #Concatenate each left and right key pair
    K = []
    for x in range(16):
        K.append(LK[x] + RK[x])

    #Permute each key according to table PC-2
    K_PC_2 = [None] * 16
    p = ""
    for x in range(16):
        pair = K[x]
        for y in range(48):
            p += pair[table_pc_2[y] - 1]
        K_PC_2[x] = p
        p = ""

    #Permute ciphertext according to table IP
    ciphertext_binary_IP = ""
    for x in range(64):
        ciphertext_binary_IP += ciphertext[table_IP[x] - 1]

    #Split permuted ciphertext into left block and right block
    lb = ciphertext_binary_IP[:32]
    rb = ciphertext_binary_IP[32:]

    #Define f-function
    def f(r_n_minus_1_integer, k_n):
        #Convert r_n_minus_1 to bits, padding with 0's if necessary
        r_n_minus_1 = decimal_to_binary(r_n_minus_1_integer)
        if(len(r_n_minus_1) < 32):
            r_n_minus_1 = r_n_minus_1.rjust(32, "0") 

        #Expand r_n_minus_1 according to expansion table E (32 to 48 bits)
        r_n_minus_1_E = ""
        for x in range(48):
            r_n_minus_1_E += r_n_minus_1[table_E[x] - 1]
        
        #Convert expanded r_n_minus1 and key to integers to facilitate XOR
        r_n_minus_1_E_integer = int(r_n_minus_1_E, 2)
        k_n_integer = int(k_n, 2)
        
        #XOR expanded r_n_minus_1 with key
        xor_output_integer = r_n_minus_1_E_integer ^ k_n_integer

        #Convert XOR output integer to bits, pad with 0's if necessary
        xor_output = decimal_to_binary(xor_output_integer)

        if(len(xor_output) < 48):
            xor_output = xor_output.rjust(48, "0")

        #Split XOR output into 8 6-bit blocks
        xor_output_temp = xor_output
        xor_output_blocks = []
        while(xor_output_temp):
            xor_output_blocks.append(xor_output_temp[:6])
            xor_output_temp = xor_output_temp[6:]

        #Find substitution box rows and columns from each 6-bit block
        rows = []
        columns = []
        for x in xor_output_blocks:
            rows.append(int((str(x[0]) + str(x[5])), 2))
            columns.append(int((str(x[1]) + str(x[2]) + str(x[3]) + str(x[4])), 2))

        #Use substitution boxes
        s_box_output = ""
        s_box_output += decimal_to_binary(table_s_box_1[rows[0]][columns[0]])[4:]
        s_box_output += decimal_to_binary(table_s_box_2[rows[1]][columns[1]])[4:]
        s_box_output += decimal_to_binary(table_s_box_3[rows[2]][columns[2]])[4:]
        s_box_output += decimal_to_binary(table_s_box_4[rows[3]][columns[3]])[4:]
        s_box_output += decimal_to_binary(table_s_box_5[rows[4]][columns[4]])[4:]
        s_box_output += decimal_to_binary(table_s_box_6[rows[5]][columns[5]])[4:]
        s_box_output += decimal_to_binary(table_s_box_7[rows[6]][columns[6]])[4:]
        s_box_output += decimal_to_binary(table_s_box_8[rows[7]][columns[7]])[4:]

        #Permute substitution box output according to table P
        s_box_output_P = ""
        for x in range(32):
            s_box_output_P += s_box_output[table_P[x] - 1]

        #Return permuted substitution box output as integer
        return int(s_box_output_P, 2)        

#Convert lb and rb to integers
    lb0_integer = int(lb, 2)
    rb0_integer = int(rb, 2)

    #set lb1 equal to rb0 and rb 1 equal to XOR lb0 with f-function output
    lb1_integer = rb0_integer
    rb1_integer = lb0_integer ^ f(rb0_integer, K_PC_2[15])
    
    #Do this for all 15 rounds
    lb2_integer = rb1_integer
    rb2_integer = lb1_integer ^ f(rb1_integer, K_PC_2[14])
    lb3_integer = rb2_integer
    rb3_integer = lb2_integer ^ f(rb2_integer, K_PC_2[13])
    lb4_integer = rb3_integer
    rb4_integer = lb3_integer ^ f(rb3_integer, K_PC_2[12])
    lb5_integer = rb4_integer
    rb5_integer = lb4_integer ^ f(rb4_integer, K_PC_2[11])
    lb6_integer = rb5_integer
    rb6_integer = lb5_integer ^ f(rb5_integer, K_PC_2[10])
    lb7_integer = rb6_integer
    rb7_integer = lb6_integer ^ f(rb6_integer, K_PC_2[9])
    lb8_integer = rb7_integer
    rb8_integer = lb7_integer ^ f(rb7_integer, K_PC_2[8])
    lb9_integer = rb8_integer
    rb9_integer = lb8_integer ^ f(rb8_integer, K_PC_2[7])
    lb10_integer = rb9_integer
    rb10_integer = lb9_integer ^ f(rb9_integer, K_PC_2[6])
    lb11_integer = rb10_integer
    rb11_integer = lb10_integer ^ f(rb10_integer, K_PC_2[5])
    lb12_integer = rb11_integer
    rb12_integer = lb11_integer ^ f(rb11_integer, K_PC_2[4])
    lb13_integer = rb12_integer
    rb13_integer = lb12_integer ^ f(rb12_integer, K_PC_2[3])
    lb14_integer = rb13_integer
    rb14_integer = lb13_integer ^ f(rb13_integer, K_PC_2[2])
    lb15_integer = rb14_integer
    rb15_integer = lb14_integer ^ f(rb14_integer, K_PC_2[1])
    lb16_integer = rb15_integer
    rb16_integer = lb15_integer ^ f(rb15_integer, K_PC_2[0])

#Convert lb16 and rb16 to bits and pad with 0's if necessary
    lb16 = decimal_to_binary(lb16_integer)
    if(len(lb16) < 32):
        lb16 = lb16.rjust(32, "0")
    rb16 = decimal_to_binary(rb16_integer)
    if(len(rb16) < 32):
        rb16 = rb16.rjust(32, "0")

    #Reverse the order of concatenated block
    rb16lb16 = rb16 + lb16

    #Permute reversed concatenated block according to IP inverse table
    plaintext_binary = ""
    for x in range(64):
        plaintext_binary += rb16lb16[table_IP_inverse[x] - 1]
    
    #Decode plaintext bits to ASCII characters
    plaintext_binary_temp = plaintext_binary
    plaintext = ""
    while(plaintext_binary_temp):
        plaintext += chr(int(plaintext_binary_temp[:8], 2))
        plaintext_binary_temp = plaintext_binary_temp[8:]

    #Return plaintext
    return plaintext

#RSA
#Define function to split plaintext into 1024-bit blocks to be encrypted and decrypted one at a time
def rsa_blocks(plaintext):    
    clear_screen()
    print_banner()
    print("Encryption Using RSA:")

    #Convert plaintext to bits
    plaintext_binary = ""
    for x in plaintext:
        plaintext_binary += decimal_to_binary(ord(x))

    #Store each 1024-bit block in an array
    plaintext_binary_temp = plaintext_binary
    plaintext_binary_blocks = []
    while(plaintext_binary_temp):
        plaintext_binary_blocks.append(plaintext_binary_temp[:1024])
        plaintext_binary_temp = plaintext_binary_temp[1024:]

    #Begin encryption
    #Encrypt each block
    ciphertext_blocks = []
    for x in plaintext_binary_blocks:
        ciphertext_blocks.append(encrypt_rsa(x))
    
    #Convert ciphertext array to bit stream
    ciphertext = ""
    for x in ciphertext_blocks:
        ciphertext += x
    
    #Print plaintext and ciphertext to screen
    print("\nplaintext: ", plaintext)
    print("ciphertext:", ciphertext)

    #Begin decryption
    print("\nDecryption Using RSA:")

    #Decrypt each ciphertext block
    plaintext_binary_blocks = []
    for x in ciphertext_blocks:
        plaintext_binary_blocks.append(decrypt_rsa(x))

    #Convert plaintext block to string
    plaintext = ""
    for x in plaintext_binary_blocks:
        plaintext += x

    #Print plaintext and ciphertext to screen
    print("\nciphertext:", ciphertext)
    print("plaintext: ", plaintext)

#Define function to encrypt with RSA
def encrypt_rsa(plaintext):

    #Declare variables
    p = 11427529967906421512279136964306012190483075001889120229053416119658562433007745433309218600650058499537976612776647283277045881634394419099743863497105373
    q = 11678982511705063837311782615385488075373585716784269133189713015963559565333423054626466435337874266742809754512689346112088306350832625579630286601311317
    n = p * q
    e = 13477

    plaintext_binary = plaintext

    #Pad with 0's if necessary
    if(len(plaintext_binary) < 1024):
        plaintext_binary = plaintext_binary.rjust(1024, '0')

    #Convert plaintext bits to integer
    plaintext_integer = int(plaintext_binary, 2)

    #Encrypt plaintext
    ciphertext_integer = pow(plaintext_integer, e, n)

    #Convert ciphertext integer to bits
    ciphertext = decimal_to_binary(ciphertext_integer)

    #Return ciphertext
    return ciphertext

#Define function to decrypt RSA
def decrypt_rsa(ciphertext):
    #Declare variables
    p = 11427529967906421512279136964306012190483075001889120229053416119658562433007745433309218600650058499537976612776647283277045881634394419099743863497105373
    q = 11678982511705063837311782615385488075373585716784269133189713015963559565333423054626466435337874266742809754512689346112088306350832625579630286601311317
    n = p * q
    e = 13477
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    #Convert ciphertext bits to integer
    ciphertext_integer = int(ciphertext, 2)

    #Decrypt ciphertext
    plaintext_integer = pow(ciphertext_integer, d, n)

    #Convert plaintext integer to bits, pad with 0's if necessary (looking for multiples of 8)
    plaintext_binary = decimal_to_binary(plaintext_integer)
    if(len(plaintext_binary) % 8 != 0):
        plaintext_binary = plaintext_binary.rjust(((len(plaintext_binary) // 8) + 1) * 8, '0')

    #Decode plaintext bits to ASCII characters
    plaintext_binary_temp = plaintext_binary
    plaintext = ""
    while(plaintext_binary_temp):
        plaintext += chr(int(plaintext_binary_temp[:8], 2))
        plaintext_binary_temp = plaintext_binary_temp[8:]

    return plaintext

#ELGAMAL
#Define function to split plaintext in 1024-bit blocks to be encrypted and decrypted one at a time
def elgamal_blocks(plaintext):
    clear_screen()
    print_banner()
    print("Encryption Using Elgamal:")

    #Convert plaintext to bits
    plaintext_binary = ""
    for x in plaintext:
        plaintext_binary += decimal_to_binary(ord(x))

    #Store each 2048-bit block in an array
    plaintext_binary_temp = plaintext_binary
    plaintext_binary_blocks = []
    while(plaintext_binary_temp):
        plaintext_binary_blocks.append(plaintext_binary_temp[:1024])
        plaintext_binary_temp = plaintext_binary_temp[1024:]

    #Begin encryption
    #Encrypt each block
    ciphertext_blocks = []
    for x in plaintext_binary_blocks:
        ciphertext_blocks.append(encrypt_elgamal(x))
    
    #Convert ciphertext array to bit stream
    ciphertext = ""
    for x in ciphertext_blocks:
        ciphertext += x

    
    #Print plaintext and ciphertext to screen
    print("\nplaintext: ", plaintext)
    print("ciphertext:", ciphertext)

    #Begin decryption
    print("\nDecryption Using Elgamal:")

    #Decrypt each ciphertext block
    plaintext_binary_blocks = []
    for x in ciphertext_blocks:
        plaintext_binary_blocks.append(decrypt_elgamal(x))

    #Convert plaintext block to string
    plaintext = ""
    for x in plaintext_binary_blocks:
        plaintext += x

    #Print plaintext and ciphertext to screen
    print("\nciphertext:", ciphertext)
    print("plaintext: ", plaintext)

#Define function to encrypt using Elgamal
def encrypt_elgamal(plaintext):
    #Bob uses a large prime number p, primitive element alpha, and chosen private key d,
    #Bob computes B and sends p, alpha and B to Alice so she can encrypt her message
    p = 140466797171509625060682992100867312127606840150873391630431829970481891783371067901027009270374164143811189367323508123224061762780352248988975508524269500233649842892572275923556207487683196920401700610475373840340108729736624563511464109111837706326211797449412429216646071117306336530338253714675429766469
    alpha = 3
    d = 12
    B = pow(alpha, d, p)

    #Alice chooses a value i, computes kE, and kM
    i = 5
    kE = pow(alpha, i, p)
    kM = pow(B, i, p)

    plaintext_binary = plaintext

    #Pad with 0's if necessary
    if(len(plaintext_binary) < 1024):
        plaintext_binary = plaintext_binary.rjust(1024, '0')

    #Convert plaintext bits to integer
    plaintext_integer = int(plaintext_binary, 2)

    #Alice encrypts her message with kM
    ciphertext_integer = (plaintext_integer * kM) % p

    #Convert ciphertext integer to bits
    ciphertext = decimal_to_binary(ciphertext_integer)

    #Return ciphertext
    return ciphertext

#Define function to decrypt Elgamal
def decrypt_elgamal(ciphertext):
    #Recall the values Bob already knows
    p = 140466797171509625060682992100867312127606840150873391630431829970481891783371067901027009270374164143811189367323508123224061762780352248988975508524269500233649842892572275923556207487683196920401700610475373840340108729736624563511464109111837706326211797449412429216646071117306336530338253714675429766469
    d = 12

    #Recivees kE from Alice
    kE = pow(3, 5, p)

    #Convert ciphertext bits to integer
    ciphertext_integer = int(ciphertext, 2)

    #Bob decrypts ciphertext
    plaintext_integer = ciphertext_integer * pow(kE, (p - d - 1), p) % p

    #Convert plaintext integer to bits, pad with 0's if necessary (looking for multiples of 8)
    plaintext_binary = decimal_to_binary(plaintext_integer)
    if(len(plaintext_binary) % 8 != 0):
        plaintext_binary = plaintext_binary.rjust(((len(plaintext_binary) // 8) + 1) * 8, '0')

    #Decode plaintext bits to ASCII characters
    plaintext_binary_temp = plaintext_binary
    plaintext = ""
    while(plaintext_binary_temp):
        plaintext += chr(int(plaintext_binary_temp[:8], 2))
        plaintext_binary_temp = plaintext_binary_temp[8:]

    #Return plaintext
    return plaintext

###MAIN PROGRAM LOOP
option_continue = "Y"
while(option_continue == "Y" or option_continue == "y"):
    main_menu()
    option_continue = input("\nEnter Y to continue encrypting messages; enter any other key to exit:")
print("\n\nThank you for using my program.\n-Dan\n")
    



