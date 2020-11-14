<?php
/**
 * Classe per la gestione del JSON Web Token
 */

namespace Farm\Libraries;

class JWT
{
    /**
     * $key
     *
     * @var string
     */
    private $key = 'My53cretK37';

    /**
     * $header
     *
     * @var array
     */
    private $header = [
        'typ' => 'JWT',
        'alg' => 'HS256'
    ];

    /**
     * @fn encode
     * 
     * @param array $payload
     * @return void
     */
    public function encode(array $payload = NULL)
    {
        $header = json_encode($this->header);

        $encode_header = $this->base64UrlEncode($header);
        $encode_payload = $this->base64UrlEncode($payload);

        $signature = hash_hmac('sha256', $encode_header . "." . $encode_payload, $this->key, true);

        $encode_signature = $this->base64UrlEncode($signature);

        return $encode_header . "." . $encode_payload . "." . $encode_signature;
    }

    /**
     * @fn verify
     *
     * @param string $jwt
     * @return boolean
     */
    public function verify(string $jwt): boolean
    {
        $segments = explode('.', $jwt);
        $segment['payload'] = base64_decode($segments[1]);

        return ($jwt != $this->encode($segment['payload'])) ? false : true;
    }

    /**
     * @fn base64Urlencode
     *
     * @param [type] $text
     * @return string
     */
    protected function base64UrlEncode($text): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    }

    /**
     * @fn getPayload
     *
     * @return void
     */
    public function getPayload(string $jwt)
    {
        $segments = explode('.', $jwt);
        
        return base64_decode($segments[1]);
    }
}