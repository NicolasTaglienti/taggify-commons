<?php

namespace Taggify\Common\Security;

interface Encryptor
{
    public function encrypt($raw_string);

    public function decrypt($encrypted_string);

    public function generateSecureTimestamp();
}