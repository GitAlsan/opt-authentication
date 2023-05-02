<?php declare(strict_types = 1);

namespace GitAlsan\Test;

use Nette\Application\UI\Presenter;
use Nette\DI\CompilerExtension;
use Nette\Schema\Schema;
use Nette\Schema\Expect;

class aptAuthenticationExtension extends CompilerExtension
{
	public function getConfigSchema(): Schema
	{
		return Expect::structure([
			'algorithm' => Expect::string()->default('SHA1'),
			'digits' => Expect::int()->default(6),
			'period' => Expect::int()->default(30),
			'googleQrLink' => Expect::string()->default('https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl='),
		]);
	}

	public function loadConfiguration()
	{
		$algorithm = $this->config->algorithm;
		$digits = $this->config->digits;
		$period = $this->config->period;
		$googleQrLink = $this->config->googleQrLink;
	}

	private function base32_encode($data): string {
    	static $codes = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    	$bits = "";
    	foreach (str_split($data) as $c) {
        	$bits .= sprintf("%08b", ord($c));
    	}
		$return = "";
		foreach (str_split($bits, 5) as $c) {
			$return .= $codes[bindec($c)];
		}
		return $return;
	}

	// Vygenerovani QR kodu
	public function getOtpQrUrl(string $issuer, string $user, string $secret): string
	{
		$otpAuth = "otpauth://totp/" . rawurlencode($issuer) . ":$user?secret=" . base32_encode($secret) . "&issuer=" . rawurlencode($issuer);
		return $this->config->googleQrLink . urlencode($otpAuth);
	}

	// Při ověřování kódu zadaného uživatelem vygenerujeme ten stejný kód
	// Takto vygenerovaný kód stačí porovnat s tím, co zadal uživatel, protože aplikace ho generuje stejně. Funkce pracuje s šesticifernými kódy,
	// které jsou výchozí. Pokud ověření selže, tak bych doporučoval porovnat i kód pro předchozí (pro případ, že uživatel kód nestihl opsat včas)
	// a následující (pokud se rozchází čas) $timeSlot.
	public function getOtp(string $secret, string $timeSlot): int
	{
		$data = str_pad(pack('N', $timeSlot), 8, "\0", STR_PAD_LEFT);
		$hash = hash_hmac('sha1', $data, $secret, true);
		$offset = ord(substr($hash, -1)) & 0xF;
		$unpacked = unpack('N', substr($hash, $offset, 4));
		return ($unpacked[1] & 0x7FFFFFFF) % 1e6;
	}
}