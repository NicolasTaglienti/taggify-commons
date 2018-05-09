<?php

namespace Taggify\Common\Security;

final class McryptEncryptor implements Encryptor
{
    const TIMESTAMP_SALT = '%t%a#gg|iff?y99';
    const VALIDATION_KEY = 'tagg1f1&123$';
    const IV = '12345678';

    private function __construct()
    {}

    public static function create()
    {
        return new self;
    }

    private function initMcrypt()
    {
        $td = mcrypt_module_open(MCRYPT_BLOWFISH, '', 'cbc', '');
        mcrypt_generic_init($td, self::VALIDATION_KEY, self::IV);

        return $td;
    }

    private function deinitMcrypt($td)
    {
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
    }

    private function encode($string)
    {
        $data = base64_encode($string);
        $data = str_replace(array('+','/','='), array('-','_','.'), $data);
        return $data;
    }

    private function decode($string)
    {
        $data = str_replace(array('-','_','.'), array('+','/','='), $string);

        return base64_decode($data);
    }

    public function encrypt($raw_string)
    {
        $cipher = $this->initMcrypt();
        $encrypted = '';
        $encrypted = mcrypt_generic($cipher, $raw_string);
        $encrypted = $this->encode($encrypted);
        $this->deinitMcrypt($cipher);

        return $encrypted;
    }


    public function decrypt($encrypted_string)
    {
        $cipher = $this->initMcrypt();
        $decoded_string = $this->decode($encrypted_string);
        $decrypted = mdecrypt_generic($cipher,  $decoded_string);
        $this->deinitMcrypt($cipher);

        return rtrim($decrypted,"\0");
    }

    public function generateSecureTimestamp()
    {
        $time = [];
        $time['ts'] = base64_encode(microtime(true));
        $time['tc'] = md5($time['ts'] . crc32(self::TIMESTAMP_SALT) . self::TIMESTAMP_SALT);

        return $time;
    }
}