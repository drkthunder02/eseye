<?php

/*
 * This file is part of SeAT
 *
 * Copyright (C) 2015, 2016, 2017  Leon Jacobs
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use Firebase\JWT\JWT;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Seat\Eseye\Configuration;
use Seat\Eseye\Containers\EsiAuthentication;
use Seat\Eseye\Containers\EsiResponse;
use Seat\Eseye\Exceptions\InvalidAuthenticationException;
use Seat\Eseye\Exceptions\RequestFailedException;
use Seat\Eseye\Fetchers\GuzzleFetcher;
use Seat\Eseye\Log\NullLogger;

class GuzzleFetcherTest extends TestCase
{

    /**
     * @var GuzzleFetcher
     */
    protected $fetcher;

    public function setUp(): void
    {

        // Remove logging
        $configuration = Configuration::getInstance();
        $configuration->logger = NullLogger::class;

        $this->fetcher = new GuzzleFetcher;
    }

    public function testGuzzleFetcherInstantiation()
    {

        $this->assertInstanceOf(GuzzleFetcher::class, $this->fetcher);
    }

    public function testGuzzleGetsClientIfNoneSet()
    {

        $fetcher = new GuzzleFetcher;
        $client = $fetcher->getClient();

        $this->assertInstanceOf(Client::class, $client);
    }

    public function testGuzzleFetcherStripRefreshTokenFromUrl()
    {

        $url = 'https://esi.url/oauth?type=refresh_token&refresh_token=foo';
        $stripped = $this->fetcher->stripRefreshTokenValue($url);

        $this->assertEquals('https://esi.url/oauth?type=refresh_token', $stripped);
    }

    public function testGuzzleFetcherStripRefreshTokenFromUrlWithoutRefreshToken()
    {

        $url = 'https://esi.url/type=refresh_token';
        $stripped = $this->fetcher->stripRefreshTokenValue($url);

        $this->assertEquals('https://esi.url/type=refresh_token', $stripped);
    }

    public function testGuzzleFetcherStripRefreshTokenNoTokenMention()
    {

        $url = 'https://esi.url/foo=bar';
        $stripped = $this->fetcher->stripRefreshTokenValue($url);

        $this->assertEquals($url, $stripped);
    }

    public function testGuzzleFetcherMakeEsiResponseContainer()
    {

        $response = json_encode(['response' => 'ok']);

        $container = $this->fetcher->makeEsiResponse($response, [], 'now', 200);

        $this->assertInstanceOf(EsiResponse::class, $container);
    }

    public function testGuzzleFetcherGetAuthenticationWhenNoneSet()
    {

        $authentication = $this->fetcher->getAuthentication();

        $this->assertNull($authentication);
    }

    public function testGuzzleFetcherGetAuthenticationWhenSettingAuthentication()
    {

        $fetcher = new GuzzleFetcher(new EsiAuthentication([
            'client_id' => 'foo',
        ]));

        $this->assertInstanceOf(EsiAuthentication::class, $fetcher->getAuthentication());
    }

    public function testGuzzleSetsAuthentication()
    {

        $this->fetcher->setAuthentication(new EsiAuthentication([
            'client_id'     => 'foo',
            'secret'        => 'bar',
            'access_token'  => '_',
            'refresh_token' => 'baz',
            'token_expires' => '1970-01-01 00:00:00',
            'scopes'        => ['public'],
        ]));

        $this->assertInstanceOf(EsiAuthentication::class, $this->fetcher->getAuthentication());
    }

    public function testGuzzleFailsSettingInvalidAuthentication()
    {

        $this->expectException(InvalidAuthenticationException::class);

        $this->fetcher->setAuthentication(new EsiAuthentication([
            'client_id' => null,
        ]));
    }

    public function testGuzzleShouldFailGettingTokenWithoutAuthentication()
    {

        $this->expectException(InvalidAuthenticationException::class);

        $get_token = self::getMethod('getToken');
        $get_token->invokeArgs(new GuzzleFetcher, []);
    }

    /**
     * Helper method to set private methods public.
     *
     * @param $name
     *
     * @return \ReflectionMethod
     */
    protected static function getMethod($name)
    {

        $class = new ReflectionClass('Seat\Eseye\Fetchers\GuzzleFetcher');
        $method = $class->getMethod($name);
        $method->setAccessible(true);

        return $method;
    }

    public function testGuzzleFetcherGetPublicScopeWithoutAuthentication()
    {

        $scopes = $this->fetcher->getAuthenticationScopes();

        $this->assertEquals(1, count($scopes));
    }

    public function testGuzzleCallingWithoutAuthentication()
    {

        $mock = new MockHandler([
            new Response(200, ['X-Foo' => 'Bar'], json_encode(['foo' => 'var'])),
        ]);

        // Update the fetchers client
        $this->fetcher->setClient(new Client([
            'handler' => HandlerStack::create($mock),
        ]));

        $response = $this->fetcher->call('get', '/foo', ['foo' => 'bar']);

        $this->assertInstanceOf(EsiResponse::class, $response);
    }

    public function testGuzzleCallingWithAuthentication()
    {
        // init a JWK set
        $jwk = $this->getJwtFixtures();

        // generate a JWS Token mocking standard CCP format
        $jws = $jwt['token'];

        $mock = new MockHandler([
            // RefreshToken response
            new Response(200, ['X-Foo' => 'Bar'], json_encode([
                'access_token'  => $jws,
                'expires_in'    => 1200,
                'token_type'    => 'Bearer',
                'refresh_token' => 'bar',
            ])),
            // JWKS endpoint response
            new Response(200, [], json_encode([
                'jwks_uri' => 'https://login.eveonline.com/oauth/jwks',
            ])),
            // JWK Sets response
            new Response(200, [], json_encode([
                'keys' => [
                    $jwt['jwks']['keys'][0],
                ],
                'SkipUnresolvedJsonWebKeys' => true,
            ])),
            // ESI response
            new Response(200, ['X-Foo' => 'Bar'], json_encode(['foo' => 'var'])),
        ]);

        // Update the fetchers client
        $this->fetcher->setClient(new Client([
            'handler' => HandlerStack::create($mock),
        ]));

        // Update the fetchers authentication
        $this->fetcher->setAuthentication(new EsiAuthentication([
            'client_id'     => 'foo',
            'secret'        => 'bar',
            'access_token'  => '_',
            'refresh_token' => 'baz',
            'token_expires' => '1970-01-01 00:00:00',
            'scopes'        => ['public'],
        ]));

        $response = $this->fetcher->call('get', '/foo', ['foo' => 'bar']);

        $this->assertInstanceOf(EsiResponse::class, $response);
    }

    public function testGuzzleCallingCatchesRequestAuthenticationFailure()
    {

        $this->expectException(RequestFailedException::class);

        $mock = new MockHandler([
            new Response(401),
        ]);

        // Update the fetchers client
        $this->fetcher->setClient(new Client([
            'handler' => HandlerStack::create($mock),
        ]));

        $this->fetcher->call('get', '/foo', ['foo' => 'bar']);
    }

    public function testGuzzleFetcherMakesHttpRequest()
    {

        $mock = new MockHandler([
            new Response(200, ['X-Foo' => 'Bar'], json_encode(['foo' => 'var'])),
        ]);

        // Update the fetchers client
        $this->fetcher->setClient(new Client([
            'handler' => HandlerStack::create($mock),
        ]));

        $response = $this->fetcher->httpRequest('get', '/foo');

        $this->assertInstanceOf(EsiResponse::class, $response);

    }

    public function testGuzzleConstructsWithClientAndGetsAuthenticationScopes()
    {

        // init a JWK Set
        $jwk = $this->getJwtFixtures();

        // init a JWS Token
        $jws = $jwt['token'];

        $mock = new MockHandler([
            // JWK Endpoint
            new Response(200, [], json_encode([
                'jwks_uri' => 'https://login.eveonline.com/oauth/jwks',
            ])),
            // JWK Sets response
            new Response(200, [], json_encode([
                'keys' => [
                    $jwt['jwks']['keys'][0],
                ],
                'SkipUnresolvedJsonWebKeys' => true,
            ])),
        ]);

        // Update the fetchers client
        $client = new Client([
            'handler' => HandlerStack::create($mock),
        ]);

        // Update the fetchers authentication
        $authentication = new EsiAuthentication([
            'client_id'     => 'foo',
            'secret'        => 'bar',
            'access_token'  => $jws,
            'refresh_token' => 'baz',
            'token_expires' => '1970-01-01 00:00:00',
        ]);

        $fetcher = new GuzzleFetcher($authentication);
        $fetcher->setClient($client);

        $scopes = $fetcher->getAuthenticationScopes();

        $this->assertEquals(['foo', 'bar', 'baz', 'public'], $scopes);
    }

    /**
     * @return array<string, mixed>
     */
    private function getJwtFixtures(): array
    {
        $private_key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($private_key === false) {
            throw new runtimeException('Unable to generate a private key for test.');
        }

        $exported = openssl_pkey_export($private_key, $private_key_pem);
        $details = openssl_pkey_get_details($private_key);

        if ($exported === false || $details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException('Unable to export generated test keys.');
        }

        return [
            'jwks' => [
                'keys' => [[
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'kid' => 'JWT-Signature-Key',
                    'alg' => 'RS256',
                    'n' => $this->base64UrlEncode($details['rsa']['n']),
                    'e' => $this->base64UrlEncode($details['rsa']['e']),
                ]],
                'SkipUnresolvedJsonWebKeys' => true,
            ],
            'token' => $this->getJwsToken($private_key_pem),
        ];
    }

    /**
     * @param string $private_key
     * @return string
     */
    private function getJwsToken(string $private_key): string
    {
        $time = time();

        return JWT::encode([
            'scp' => [
                'foo',
                'bar',
                'baz',
                'public',
            ],
            'sub' => 'CHARACTER:EVE:90795931',
            'azp' => 'foo',
            'name' => 'Warlof Tutsimo',
            'owner' => 'svnSjVa1uGYyp/ZL3mfkIwkJYzQ=',
            'exp' => $time + 3600,
            'iss' => 'https://login.eveonline.com',
        ], $private_key, 'RS256', 'JWT-Signature-Key', [
            'typ' => 'JWT',
        ]);
    }

    /**
     * @param  string  $value
     * @return string
     */
    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
