#include <iostream>
#include <fstream>
#include "encryptor_decryptor.h"

using namespace std;

int main(int argc, char* argv[])
{	
	uint16_t crypto_key;
    uint16_t  input_msg;
    uint16_t  v1, v2;
    

    do {
        cout << "Input key (dec): ";
        cin >> crypto_key;
        Encryptor_Decryptor encryptor_decryptor(crypto_key);	
        
        do {
            cout << "Input message (dec): ";
            cin >> input_msg;
            
            cout << "Encrypt(1) or Decrypt(2)?: ";
            cin >> v1;
            
            if (v1 == 1)
                encryptor_decryptor.Encrypt_Msg(input_msg);
            else if (v1 == 2) 
                encryptor_decryptor.Decrypt_Msg(input_msg);
                
            cout << "Retry?  with save key (1), with new key (2), NO (other key): ";
            cin >> v2;
            cout << "\n";
        } while (v2 == 1);
    } while (v2 == 2);
	return 0;
}

