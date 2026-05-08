<?php

namespace App\Service;

use App\Entity\Device;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;

class AuthService
{
    private const REFRESH_TOKEN_LIFETIME_DAYS = 7;
    private const MAX_DEVICES_PER_USER = 5;

    public function __construct(
        private EntityManagerInterface $em,
        private JWTTokenManagerInterface $jwtManager,
        private UserPasswordHasherInterface $passwordHasher
    ) {}

    public function login(string $email, string $password, Request $request): array
    {
        $user = $this->em->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$this->passwordHasher->isPasswordValid($user, $password)) {
            throw new BadCredentialsException('Invalid credentials');
        }

        $accessToken = $this->jwtManager->create($user);
        $rawRefreshToken = $this->generateRefreshToken();
        
        $this->createDeviceRecord($user, $rawRefreshToken, $request);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $rawRefreshToken,
            'device_id' => null
        ];
    }

    private function createDeviceRecord(User $user, string $rawRefreshToken, Request $request): void
    {
        $parts = explode('.', $rawRefreshToken);
        $identifier = $parts[0];
        $secret = $parts[1];
        $hash = password_hash($secret, PASSWORD_BCRYPT);

        $device = new Device();
        $device->setUser($user);
        $device->setTokenIdentifier($identifier);
        $device->setRefreshTokenHash($hash);
        $device->setIpAddress($request->getClientIp());
        $device->setUserAgent($request->headers->get('User-Agent'));
        $device->setExpiresAt(new \DateTimeImmutable('+7 days'));
        
        $this->em->persist($device);
        $this->enforceDeviceLimit($user);
        $this->em->flush();
    }

    private function enforceDeviceLimit(User $user): void
    {
        $devices = $user->getDevices()->toArray();
        
        if (count($devices) > self::MAX_DEVICES_PER_USER) {
            usort($devices, function (Device $a, Device $b) {
                return $a->getLastUsedAt() <=> $b->getLastUsedAt();
            });

            $devicesToRemove = array_slice($devices, 0, count($devices) - self::MAX_DEVICES_PER_USER);
            
            foreach ($devicesToRemove as $oldDevice) {
                $this->em->remove($oldDevice);
            }
        }
    }
    
    public function invalidateAllUserTokens(User $user): void
    {
        foreach ($user->getDevices() as $device) {
            $this->em->remove($device);
        }
        $this->em->flush();
    }

    private function generateRefreshToken(): string
    {
        $identifier = bin2hex(random_bytes(16));
        $secret = bin2hex(random_bytes(64));
        return $identifier . '.' . $secret;
    }
}