/*
 * encryptor_decryptor.h
 * 
 * Copyright 2015 Pushkin <push@localhost.localdomain>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */


#ifndef ENCRYPTOR_DECRYPTOR_H
#define ENCRYPTOR_DECRYPTOR_H

#define DEBUG

#include <iostream>
#include <bitset>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdlib>

//~ typedef unsigned char       uint8_t;
//~ typedef unsigned short      uint16_t;
//~ typedef unsigned int        uint32_t;
//~ typedef unsigned long long  uint64_t;


enum {  
    CRYPTO_KEY_ZISE     = 10,
    ROUND_KEY_SIZE      = 8,
    INPUT_MSG_SIZE      = 8
};

using namespace std;

class Encryptor_Decryptor
{
    private:
        bitset<ROUND_KEY_SIZE> subkey_round_1;
        bitset<ROUND_KEY_SIZE> subkey_round_2;
        bitset<INPUT_MSG_SIZE> input_msg;
    // параметры, считываемы из conf-файла
        vector<uint8_t> permutation_order_P10;
        vector<uint8_t> permutation_order_P8;
        vector<uint8_t> permutation_order_IP;
        vector<uint8_t> permutation_order_E;
        vector<uint8_t> block_S1;
        vector<uint8_t> block_S2;
        vector<uint8_t> permutation_order_P;
        vector<uint8_t> permutation_order_IP_1;
        
        inline void permute_msg_IP(bitset<INPUT_MSG_SIZE> &bitset_input_msg);
        inline void split_msg(const bitset<INPUT_MSG_SIZE> &bitset_input_msg,
                              string &str_input_msg_h4, string &str_input_msg_l4);
        inline void permute_msg_with_exp(bitset<INPUT_MSG_SIZE/2> &bitset_half_msg,
                                         bitset<INPUT_MSG_SIZE> &bitset_exp_msg);
        inline void make_s_block_mixing(bitset<INPUT_MSG_SIZE> &bitset_exp_msg,
                                        bitset<INPUT_MSG_SIZE/2> &bitset_mix_msg);
        inline void permute_msg_P(bitset<INPUT_MSG_SIZE/2> &bitset_half_msg);
        void make_fajstel_function(bitset<INPUT_MSG_SIZE/2> &bitset_half_msg, 
                                   bitset<ROUND_KEY_SIZE> subkey);
        void permute_msg_IP_1(bitset<INPUT_MSG_SIZE> &bitset_msg);
           
        inline void permute_key_P10(bitset<CRYPTO_KEY_ZISE> &bitset_crypto_key);
        inline void shift_left_str(string &str, uint8_t count);
        inline void split_key(const bitset<CRYPTO_KEY_ZISE> &bitset_crypto_key,
                            string &str_crypto_key_h5, string &str_crypto_key_l5);
        void permute_key_with_comp(bitset<CRYPTO_KEY_ZISE> &bitset_crypto_key,
                                   bitset<ROUND_KEY_SIZE> &bitset_crypto_subkey);
        void make_subkeys(uint32_t crypto_key);
        
        bool parse_conf_string(string str, vector<uint8_t> &vec);
        void set_conf_params();
                
    public:
        uint8_t Encrypt_Msg(uint8_t input_msg);
        uint8_t Decrypt_Msg(uint8_t input_msg);
        Encryptor_Decryptor(uint32_t crypto_key);   
            
};

#endif /* ENCRYPTOR_DECRYPTOR_H */ 
