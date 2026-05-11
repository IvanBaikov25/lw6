<?php

namespace App\Controller;

use App\Entity\Device;
use App\Entity\User;
use App\Service\AuthService;
use App\Service\RefreshTokenService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

class AuthController extends AbstractController
{
    public function __construct(
        private AuthService $authService,
        private RefreshTokenService $refreshTokenService,
        private EntityManagerInterface $em
    ) {}

    #[Route('/api/login', name: 'api_login', methods: ['POST'])]
    public function login(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        try {
            $result = $this->authService->login($email, $password, $request);
            return $this->json($result);
        } catch (\Exception $e) {
            return $this->json(['error' => $e->getMessage()], 401);
        }
    }

    #[Route('/api/token/refresh', name: 'api_token_refresh', methods: ['POST'])]
    public function refresh(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $refreshToken = $data['refresh_token'] ?? '';

        if (!$refreshToken) {
            return $this->json(['error' => 'Refresh token required'], 400);
        }

        try {
            $result = $this->refreshTokenService->refresh($refreshToken, $request);
            return $this->json($result);
        } catch (\RuntimeException $e) {
            if (str_contains($e->getMessage(), 'Security Alert')) {
                return $this->json(['error' => 'Security Alert: Session terminated'], 403);
            }
            return $this->json(['error' => $e->getMessage()], 401);
        }
    }

    #[Route('/api/logout', name: 'api_logout', methods: ['POST'])]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function logout(Request $request, #[CurrentUser] User $user): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        $refreshToken = $data['refresh_token'] ?? '';
        
        if ($refreshToken) {
             $parts = explode('.', $refreshToken);
             if (count($parts) === 2) {
                 $identifier = $parts[0];
                 $device = $this->em->getRepository(Device::class)->findOneBy(['tokenIdentifier' => $identifier]);
                 
                 if ($device && $device->getUser() === $user) {
                     $device->setIsRevoked(true);
                     $this->em->flush();
                 }
             }
        }

        return $this->json(['message' => 'Logged out successfully']);
    }

    #[Route('/api/devices', name: 'api_devices', methods: ['GET'])]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function getDevices(#[CurrentUser] User $user): JsonResponse
    {
        $devices = $user->getDevices();
        
        $data = [];
        foreach ($devices as $device) {
            $data[] = [
                'id' => $device->getId(),
                'ip' => $device->getIpAddress(),
                'user_agent' => $device->getUserAgent(),
                'last_used_at' => $device->getLastUsedAt()?->format('Y-m-d H:i:s'),
                'expires_at' => $device->getExpiresAt()?->format('Y-m-d H:i:s'),
                'is_revoked' => $device->isRevoked(),
                'is_compromised' => $device->isCompromised(),
            ];
        }

        return $this->json($data);
    }
}