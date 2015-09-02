

#include "encryptor_decryptor.h"


void Encryptor_Decryptor::permute_msg_IP(bitset<INPUT_MSG_SIZE> &bitset_input_msg)
{
    bitset<INPUT_MSG_SIZE> tmp_bitset_input_msg(bitset_input_msg);
    for (uint8_t i = 0; i < INPUT_MSG_SIZE; ++i)
        bitset_input_msg[i] = tmp_bitset_input_msg[INPUT_MSG_SIZE - 1 - 
                                                    permutation_order_IP[i]];    
}


void Encryptor_Decryptor::split_msg(const bitset<INPUT_MSG_SIZE> &bitset_input_msg,
                              string &str_input_msg_h4, string &str_input_msg_l4)
{
    str_input_msg_h4 = bitset_input_msg.to_string();
    str_input_msg_l4 = str_input_msg_h4.substr(INPUT_MSG_SIZE/2, INPUT_MSG_SIZE/2);
    str_input_msg_h4.resize(INPUT_MSG_SIZE/2);      
}                          


void Encryptor_Decryptor::permute_msg_with_exp(bitset<INPUT_MSG_SIZE/2> &bitset_half_msg,
                                               bitset<INPUT_MSG_SIZE> &bitset_exp_msg)
{
    for (uint8_t i = 0; i < INPUT_MSG_SIZE; ++i)
        bitset_exp_msg[i] = bitset_half_msg[INPUT_MSG_SIZE/2 - 1 - 
                                            permutation_order_E[i]];   
}


void Encryptor_Decryptor::make_s_block_mixing(bitset<INPUT_MSG_SIZE> &bitset_exp_msg,
                                              bitset<INPUT_MSG_SIZE/2> &bitset_mix_msg)
{
// выбираем старшие 2 бита для bitset_mix_msg из таблицы S1
    uint8_t raw = (uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-1]) << 1) |
                   uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-4]);
    uint8_t col = (uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-2]) << 1) |
                   uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-3]);
    uint8_t block_cell = block_S1[raw*4 + col] + 1;  
    bitset_mix_msg[INPUT_MSG_SIZE/2 - 1] = (block_cell >> 1) & 0x01;
    bitset_mix_msg[INPUT_MSG_SIZE/2 - 2] = block_cell & 0x01;
    
// выбираем младшие 2 бита для bitset_mix_msg из таблицы S2
    raw = (uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-5]) << 1) |
           uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-8]);
    col = (uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-6]) << 1) |
           uint8_t(bitset_exp_msg[INPUT_MSG_SIZE-7]);  
    block_cell = block_S2[raw*4 + col] + 1;
    bitset_mix_msg[INPUT_MSG_SIZE/2 - 3] = (block_cell >> 1) & 0x01;
    bitset_mix_msg[INPUT_MSG_SIZE/2 - 4] = block_cell & 0x01;
}                         


void Encryptor_Decryptor::permute_msg_P(bitset<INPUT_MSG_SIZE/2> &bitset_half_msg)
{
    bitset<INPUT_MSG_SIZE/2> tmp_bitset_half_msg(bitset_half_msg);
    for (uint8_t i = 0; i < INPUT_MSG_SIZE/2; ++i)
        bitset_half_msg[i] = tmp_bitset_half_msg[INPUT_MSG_SIZE/2 - 1 - 
                                            permutation_order_P[i]];   
}


void Encryptor_Decryptor::make_fajstel_function(bitset<INPUT_MSG_SIZE/2> &bitset_half_msg, 
                                                bitset<ROUND_KEY_SIZE> subkey)
{
// перестановка с расширением E
    bitset<INPUT_MSG_SIZE> bitset_exp_msg;
    permute_msg_with_exp(bitset_half_msg, bitset_exp_msg);

// xor полученного расширенного сообщения с ключем раунда 
    bitset_exp_msg ^= subkey;

// применяем к расширенному сообщению смешивание с помощью S-блоков
    make_s_block_mixing(bitset_exp_msg, bitset_half_msg);
    
// перестановка P
    permute_msg_P(bitset_half_msg);
}


void Encryptor_Decryptor::permute_msg_IP_1(bitset<INPUT_MSG_SIZE> &bitset_msg)
{
    bitset<INPUT_MSG_SIZE> tmp_bitset_msg(bitset_msg);
    for (uint8_t i = 0; i < INPUT_MSG_SIZE; ++i)
        bitset_msg[i] = tmp_bitset_msg[INPUT_MSG_SIZE - 1 - permutation_order_IP_1[i]];    
}


uint8_t Encryptor_Decryptor::Encrypt_Msg(uint8_t input_msg)
{
// преобразование целочисленного криптоключа в битовый набор
    bitset<INPUT_MSG_SIZE> bitset_input_msg(input_msg);
    string tmp_str = bitset_input_msg.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "ENCRYPT MESSAGE:       " << tmp_str << "    (" <<  
            bitset_input_msg.to_ulong() << ")"<< "\n";
    
// начальная перестановка IP
    permute_msg_IP(bitset_input_msg);
#ifdef DEBUG
    tmp_str = bitset_input_msg.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "bitset_input_msg_IP:   " << tmp_str << "\n";
#endif

// разбиваем битовый набор на две строки 
    string str_input_msg_h4, str_input_msg_l4;
    split_msg(bitset_input_msg, str_input_msg_h4, str_input_msg_l4);

// применяем функцию Файстеля (F) первого раунда
    bitset<INPUT_MSG_SIZE/2> bitset_msg_f1(str_input_msg_l4);
    make_fajstel_function(bitset_msg_f1, subkey_round_1);
    bitset_msg_f1 ^= bitset<INPUT_MSG_SIZE/2>(str_input_msg_h4);

// применяем функцию Файстеля (F) второго раунда
    bitset<INPUT_MSG_SIZE/2> bitset_msg_f2(bitset_msg_f1);
    make_fajstel_function(bitset_msg_f2, subkey_round_2);
    bitset_msg_f2 ^= bitset<INPUT_MSG_SIZE/2>(str_input_msg_l4);

// склеиваем частичные сообщения полученные по итогам двух функций F
    string str_msg_f = 
        bitset_msg_f2.to_string<char, string::traits_type, string::allocator_type>() +
        bitset_msg_f1.to_string<char, string::traits_type, string::allocator_type>();
    bitset<INPUT_MSG_SIZE> bitset_msg_f(str_msg_f); 
#ifdef DEBUG
    tmp_str = bitset_msg_f.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "bitset_msg_f:          " << tmp_str << "\n";
#endif
    
// начальная перестановка IP_1
    permute_msg_IP_1(bitset_msg_f);
    tmp_str = bitset_msg_f.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "ENCRYPTED MESSAGE:     " << tmp_str << "    (" <<  
            bitset_msg_f.to_ulong() << ")"<< "\n";

    cout << "========================================" << "\n\n";
    return bitset_msg_f.to_ulong();
}


uint8_t Encryptor_Decryptor::Decrypt_Msg(uint8_t input_msg)
{
// преобразование целочисленного криптоключа в битовый набор
    bitset<INPUT_MSG_SIZE> bitset_input_msg(input_msg);
    string tmp_str = bitset_input_msg.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "DECRYPT MESSAGE:       " << tmp_str << "    (" << 
            bitset_input_msg.to_ulong() << ")"<< "\n";
    
// начальная перестановка IP
    permute_msg_IP(bitset_input_msg);
#ifdef DEBUG
    tmp_str = bitset_input_msg.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "bitset_input_msg_IP:   " << tmp_str << "\n";
#endif

// разбиваем битовый набор на две строки 
    string str_input_msg_h4, str_input_msg_l4;
    split_msg(bitset_input_msg, str_input_msg_h4, str_input_msg_l4);

// применяем функцию Файстеля (F) второго раунда
    bitset<INPUT_MSG_SIZE/2> bitset_msg_f2(str_input_msg_l4);
    make_fajstel_function(bitset_msg_f2, subkey_round_2);
    bitset_msg_f2 ^= bitset<INPUT_MSG_SIZE/2>(str_input_msg_h4);
    
// применяем функцию Файстеля (F) первого раунда
    bitset<INPUT_MSG_SIZE/2> bitset_msg_f1(bitset_msg_f2);
    make_fajstel_function(bitset_msg_f1, subkey_round_1);
    bitset_msg_f1 ^= bitset<INPUT_MSG_SIZE/2>(str_input_msg_l4);

// склеиваем частичные сообщения полученные по итогам двух функций F
    string str_msg_f = 
        bitset_msg_f1.to_string<char, string::traits_type, string::allocator_type>() +
        bitset_msg_f2.to_string<char, string::traits_type, string::allocator_type>();
    bitset<INPUT_MSG_SIZE> bitset_msg_f(str_msg_f); 
#ifdef DEBUG
    tmp_str = bitset_msg_f.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "bitset_msg_f:          " << tmp_str << "\n";
#endif
    
// начальная перестановка IP_1
    permute_msg_IP_1(bitset_msg_f);
    tmp_str = bitset_msg_f.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "DECRYPTED MESSAGE:     " << tmp_str << "    (" <<  
            bitset_msg_f.to_ulong() << ")"<< "\n";

    cout << "========================================" << "\n\n";
    return bitset_msg_f.to_ulong();
}


//=========================================================================================

void Encryptor_Decryptor::permute_key_P10(bitset<CRYPTO_KEY_ZISE> &bitset_crypto_key)
{
    bitset<CRYPTO_KEY_ZISE> tmp_bitset_crypto_key(bitset_crypto_key);
    for (uint8_t i = 0; i < CRYPTO_KEY_ZISE; ++i)
        bitset_crypto_key[i] = tmp_bitset_crypto_key[CRYPTO_KEY_ZISE - 1 - 
                                                    permutation_order_P10[i]];
}


void Encryptor_Decryptor::shift_left_str(string &str, uint8_t count)
{
    rotate(str.begin(), str.begin()+count, str.end());
} 


void Encryptor_Decryptor::split_key(const bitset<CRYPTO_KEY_ZISE> &bitset_crypto_key, 
                                string &str_crypto_key_h5, string &str_crypto_key_l5) 
{
    str_crypto_key_h5 = bitset_crypto_key.to_string();
    str_crypto_key_l5 = str_crypto_key_h5.substr(CRYPTO_KEY_ZISE/2, CRYPTO_KEY_ZISE/2);
    str_crypto_key_h5.resize(CRYPTO_KEY_ZISE/2);    
}


void Encryptor_Decryptor::permute_key_with_comp(bitset<CRYPTO_KEY_ZISE> &bitset_crypto_key,
                                            bitset<ROUND_KEY_SIZE> &bitset_crypto_subkey) 
{
    for (uint8_t i = 0; i < ROUND_KEY_SIZE; ++i)
        bitset_crypto_subkey[i] = bitset_crypto_key[CRYPTO_KEY_ZISE - 1 - 
                                                    permutation_order_P8[i]];
    
}


void Encryptor_Decryptor::make_subkeys(uint32_t crypto_key)
{
// преобразование целочисленного криптоключа в битовый набор
    bitset<CRYPTO_KEY_ZISE> bitset_crypto_key(crypto_key);
#ifdef DEBUG
    string tmp_str = bitset_crypto_key.to_string<char, string::traits_type, 
                                                string::allocator_type>();
    cout << "CRYPTO_KEY:            " << tmp_str << "  (" << 
            bitset_crypto_key.to_ulong() << ")"<< "\n";
#endif
    
// начальное преобразование ключа P10
    permute_key_P10(bitset_crypto_key);
#ifdef DEBUG
    tmp_str = bitset_crypto_key.to_string<char, string::traits_type, 
                                          string::allocator_type>();
    cout << "crypto_key_P10:        " << tmp_str << "\n";
#endif

// разбиваем битовый набор на две строки, т.к. его не удобно сдвигать по циклу
// а вот обычные std::string удобно с помощью std::rotate
    string str_crypto_key_h5, str_crypto_key_l5;
    split_key(bitset_crypto_key, str_crypto_key_h5, str_crypto_key_l5);
    
// циклический сдвиг влево полученых половинок на 1 бит 
    shift_left_str(str_crypto_key_h5, 1);
    shift_left_str(str_crypto_key_l5, 1);
    
// получение подключа первого раунда (K1) перестановкой со сжатием (P8)
    bitset<CRYPTO_KEY_ZISE> bitset_crypto_key_for_round_1(str_crypto_key_h5 + 
                                                          str_crypto_key_l5);
    permute_key_with_comp(bitset_crypto_key_for_round_1, subkey_round_1);
#ifdef DEBUG
    tmp_str = subkey_round_1.to_string<char, string::traits_type, 
                                          string::allocator_type>();
    cout << "SUBKEY ROUND 1:        " << tmp_str << "\n";
#endif

// циклический сдвиг влево полученых половинок еще на 2 бита 
    shift_left_str(str_crypto_key_h5, 2);
    shift_left_str(str_crypto_key_l5, 2);
    
// получение подключа второго раунда (K2) перестановкой со сжатием (P8)
    bitset<CRYPTO_KEY_ZISE> bitset_crypto_key_for_round_2(str_crypto_key_h5 + 
                                                          str_crypto_key_l5);
    permute_key_with_comp(bitset_crypto_key_for_round_2, subkey_round_2);
#ifdef DEBUG
    tmp_str = subkey_round_2.to_string<char, string::traits_type, 
                                          string::allocator_type>();
    cout << "SUBKEY ROUND 2:        " << tmp_str << "\n";
#endif
    cout << "========================================" << "\n\n";
}


//=========================================================================================

bool Encryptor_Decryptor::parse_conf_string(string str, vector<uint8_t> &vec)
{
    try {
        int16_t pos = str.find(':');
        str.erase(0, pos + 1);
        string token;
        while ((pos = str.find(',')) != -1) {
            token = str.substr(0, pos);
            vec.insert(vec.begin(), stoi(token)-1);
            str.erase(0, pos + 1);
        }
        token = str.substr(0, str.size());
        vec.insert(vec.begin(), atoi(token.c_str())-1);
        return true;
    } catch (exception &err) {
        cout << "\n" << err.what() << "\n";
        return false;
    }
} 


void Encryptor_Decryptor::set_conf_params()
{
// инициализация порядка для начального преобразования-перестановки P10
    string str_permutation_order_P10 = ":3,5,2,7,4,10,1,9,8,6";
    parse_conf_string(str_permutation_order_P10, permutation_order_P10);
    
// инициализация порядка для перестановки со сжатием P8
    string str_permutation_order_P8 = ":6,3,7,4,8,5,10,9";
    parse_conf_string(str_permutation_order_P8, permutation_order_P8);
       
// инициализация порядка для начальной перестановки IP 
    string str_permutation_order_IP = ":2,6,3,1,4,8,5,7";
    parse_conf_string(str_permutation_order_IP, permutation_order_IP);  
    
// инициализация порядка для перестановки с расширением E  
    string str_permutation_order_E = ":4,1,2,3,2,3,4,1";
    parse_conf_string(str_permutation_order_E, permutation_order_E);  
      
// инициализация S-блоков
    string str_block_S1 = ":1,0,3,2,3,2,1,0,0,2,1,3,3,1,3,1";
    string str_block_S2 = ":1,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3";
    parse_conf_string(str_block_S1, this->block_S1);
    reverse(this->block_S1.begin(), this->block_S1.end());
    parse_conf_string(str_block_S2, this->block_S2);
    reverse(this->block_S2.begin(), this->block_S2.end());
    
// инициализация порядка для перестановки P 
    string str_permutation_order_P = ":2,4,3,1";
    parse_conf_string(str_permutation_order_P, permutation_order_P);  
    
// инициализация порядка для начальной перестановки IP_1 
    string str_permutation_order_IP_1 = ":4,1,3,5,7,2,8,6";
    parse_conf_string(str_permutation_order_IP_1, permutation_order_IP_1);  
}


Encryptor_Decryptor::Encryptor_Decryptor(uint32_t crypto_key)
{
    set_conf_params();         // установка конфигурационных параметров алгоритма 
    make_subkeys(crypto_key);  // выработка подключей для 1-ого (K1) и 2-ого (K2) раундов 
}


