<?php

namespace App\Service;

use App\Entity\Device;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;

class RefreshTokenService
{
    public function __construct(
        private EntityManagerInterface $em,
        private JWTTokenManagerInterface $jwtManager
    ) {}

    public function refresh(string $rawRefreshToken, Request $request): array
    {
        $parts = explode('.', $rawRefreshToken);
        if (count($parts) !== 2) {
            throw new \RuntimeException('Invalid refresh token format');
        }
        
        $identifier = $parts[0];
        $secret = $parts[1];

        $device = $this->em->getRepository(Device::class)->findOneBy(['tokenIdentifier' => $identifier]);

        if (!$device) {
            throw new \RuntimeException('Invalid refresh token');
        }

        if ($device->isRevoked() || $device->isCompromised()) {
            $this->handleCompromisedDevice($device);
            throw new \RuntimeException('Security Alert: Token Reuse Detected');
        }

        if ($device->getExpiresAt() < new \DateTimeImmutable()) {
            throw new \RuntimeException('Refresh token expired');
        }

        if (!password_verify($secret, $device->getRefreshTokenHash())) {
            throw new \RuntimeException('Invalid refresh token secret');
        }

        $user = $device->getUser();
        $device->setIsRevoked(true);
        
        $newAccessToken = $this->jwtManager->create($user);
        $newRawRefreshToken = $this->generateRefreshToken();
        
        $newParts = explode('.', $newRawRefreshToken);
        $newIdentifier = $newParts[0];
        $newSecret = $newParts[1];
        
        $newDevice = new Device();
        $newDevice->setUser($user);
        $newDevice->setTokenIdentifier($newIdentifier);
        $newDevice->setRefreshTokenHash(password_hash($newSecret, PASSWORD_BCRYPT));
        $newDevice->setIpAddress($request->getClientIp());
        $newDevice->setUserAgent($request->headers->get('User-Agent'));
        $newDevice->setExpiresAt(new \DateTimeImmutable('+7 days'));
        
        $this->em->persist($newDevice);
        $this->enforceDeviceLimit($user);
        $this->em->flush();

        return [
            'access_token' => $newAccessToken,
            'refresh_token' => $newRawRefreshToken
        ];
    }

    private function handleCompromisedDevice(Device $compromisedDevice): void
    {
        $user = $compromisedDevice->getUser();
        $compromisedDevice->setIsCompromised(true);
        
        foreach ($user->getDevices() as $device) {
            $this->em->remove($device);
        }
        
        $this->em->flush();
    }
    
    private function enforceDeviceLimit(User $user): void
    {
         $devices = $user->getDevices()->toArray();
         if (count($devices) > 5) {
             usort($devices, function (Device $a, Device $b) {
                 return $a->getLastUsedAt() <=> $b->getLastUsedAt();
             });
             
             $toRemove = array_slice($devices, 0, count($devices) - 5);
             foreach ($toRemove as $d) {
                 $this->em->remove($d);
             }
         }
    }
    
    private function generateRefreshToken(): string
    {
        $identifier = bin2hex(random_bytes(16));
        $secret = bin2hex(random_bytes(64));
        return $identifier . '.' . $secret;
    }
}