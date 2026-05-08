<?php

namespace App\EventSubscriber;

use App\Entity\User;
use App\Service\AuthService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\PasswordAuthenticatedEvent;

class PasswordChangeSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private EntityManagerInterface $em,
        private AuthService $authService
    ) {}

    public static function getSubscribedEvents(): array
    {
        return [
            PasswordAuthenticatedEvent::class => 'onPasswordChanged',
        ];
    }

    public function onPasswordChanged(PasswordAuthenticatedEvent $event): void
    {
        $user = $event->getUser();
        
        if ($user instanceof User) {
            $this->authService->invalidateAllUserTokens($user);
        }
    }
}