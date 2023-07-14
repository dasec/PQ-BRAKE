/**
 *  Server class
 */
#pragma once
#include "../oqs_cpp.h"

class Server
{
public:

    oqs::bytes  public_key,
                secret_key,
                ephemeral_public_key,
                ephemeral_secret_key,
                ciphertext,
                shared_secret;
};

