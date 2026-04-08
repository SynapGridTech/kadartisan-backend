import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { Role } from '@prisma/client';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true; // no role restriction
    }

    const { user } = context.switchToHttp().getRequest();

    console.log('🔍 RolesGuard - Required:', requiredRoles, 'User:', user?.fullName, 'User Role:', user?.role);

    // If no user or no role, deny access
    if (!user || !user.role) {
      console.log('❌ Access denied: No user or role');
      return false;
    }

    const hasRole = requiredRoles.includes(user.role);
    console.log(hasRole ? '✅ Access granted' : '❌ Access denied: Role mismatch');
    
    return hasRole;
  }
}
