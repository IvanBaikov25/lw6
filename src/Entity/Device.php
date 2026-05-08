<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Device
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(inversedBy: 'devices')]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $user = null;

    #[ORM\Column(length: 255, unique: true)]
    private ?string $tokenIdentifier = null;

    #[ORM\Column(length: 255)]
    private ?string $refreshTokenHash = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $ipAddress = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $userAgent = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $expiresAt = null;

    #[ORM\Column]
    private bool $isRevoked = false;

    #[ORM\Column]
    private bool $isCompromised = false;

    #[ORM\Column]
    private ?\DateTimeImmutable $lastUsedAt = null;

    public function __construct()
    {
        $this->lastUsedAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function setUser(?User $user): static
    {
        $this->user = $user;
        return $this;
    }

    public function getTokenIdentifier(): ?string
    {
        return $this->tokenIdentifier;
    }

    public function setTokenIdentifier(string $tokenIdentifier): static
    {
        $this->tokenIdentifier = $tokenIdentifier;
        return $this;
    }

    public function getRefreshTokenHash(): ?string
    {
        return $this->refreshTokenHash;
    }

    public function setRefreshTokenHash(string $refreshTokenHash): static
    {
        $this->refreshTokenHash = $refreshTokenHash;
        return $this;
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function setIpAddress(?string $ipAddress): static
    {
        $this->ipAddress = $ipAddress;
        return $this;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function setUserAgent(?string $userAgent): static
    {
        $this->userAgent = $userAgent;
        return $this;
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(\DateTimeImmutable $expiresAt): static
    {
        $this->expiresAt = $expiresAt;
        return $this;
    }

    public function isRevoked(): bool
    {
        return $this->isRevoked;
    }

    public function setIsRevoked(bool $isRevoked): static
    {
        $this->isRevoked = $isRevoked;
        return $this;
    }

    public function isCompromised(): bool
    {
        return $this->isCompromised;
    }

    public function setIsCompromised(bool $isCompromised): static
    {
        $this->isCompromised = $isCompromised;
        return $this;
    }

    public function getLastUsedAt(): ?\DateTimeImmutable
    {
        return $this->lastUsedAt;
    }

    public function setLastUsedAt(\DateTimeImmutable $lastUsedAt): static
    {
        $this->lastUsedAt = $lastUsedAt;
        return $this;
    }
}