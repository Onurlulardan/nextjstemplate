# NextJS Starter

A modern and scalable system. Developed with Next.js 15, TypeScript, Prisma, and Ant Design.

## Features

- Modern and responsive user interface (Ant Design v5)
- Advanced authentication and authorization system
- Multi-organization support
- Detailed permission and role management
- Dark/Light theme support
- Real-time data synchronization
- Mobile-responsive design

### Security Logs

The system keeps track of all authentication attempts, including:

- Login attempts (successful/failed)
- IP addresses
- Browser information
- Login timestamps

## Technology Stack

- **Framework**: [Next.js 15](https://nextjs.org/) (App Router)
- **Language**: [TypeScript](https://www.typescriptlang.org/)
- **Database**: [PostgreSQL](https://www.postgresql.org/)
- **ORM**: [Prisma](https://www.prisma.io/)
- **UI**: [Ant Design](https://ant.design/)
- **Authentication**: [NextAuth.js](https://next-auth.js.org/)

## Project Structure

```
nextstarter/
├── app/                         # Next.js App Router structure
│   ├── (protected)/             # Protected routes
│   │   ├── dashboard/           # Dashboard and statistics
│   │   │   ├── page.tsx         # Main dashboard page
│   │   │   └── components/      # Dashboard components
│   │   └── administrations/     # Administration panel
│   │       ├── users/           # User management
│   │       │   ├── page.tsx     # User list
│   │       │   └── profile/     # Profile management
│   │       ├── organizations/   # Organization management
│   │       ├── roles/           # Role management
│   │       └── permissions/     # Permission management
│   ├── api/                     # API endpoints
│   │   ├── auth/                # Authentication APIs
│   │   ├── dashboard/           # Dashboard APIs
│   │   │   ├── stats/           # Statistics APIs
│   │   │   └── activity/        # Activity APIs
│   │   └── administrations/     # Administration APIs
│   │       ├── users/           # User APIs
│   │       ├── organizations/   # Organization APIs
│   │       ├── roles/           # Role APIs
│   │       ├── permissions/     # Permission APIs
│   │       ├── resources/       # Resource APIs
│   │       └── actions/         # Action APIs
│   └── auth/                    # Authentication pages
├── contexts/                    # React Contexts
│   └── NotificationContext.tsx  # Notification management
├── lib/                         # Helper functions and services
│   ├── apiClient/               # API client
│   │   └── index.ts             # Central API operations
│   ├── auth/                    # Authentication and authorization
│   │   ├── auth-options.ts      # NextAuth configuration
│   │   ├── permissions.ts       # Permission control hooks
│   │   └── session.ts           # Session management
│   └── prisma.ts                # Prisma client
├── hooks/                       # Custom React hooks
│   └── useNotificationSetup.ts  # Notification hook
└── prisma/                      # Database schema
    ├── schema.prisma            # Prisma schema definitions
    └── migrations/              # Database migrations
```

## Detailed Permission System Explanation

### 1. Basic Concepts

#### Resource

Represents protected entities in the system.

```typescript
// Example resource definitions
const resources = [
  { name: 'Product', slug: 'product' },
  { name: 'Customer', slug: 'customer' },
  { name: 'Order', slug: 'order' },
];
```

#### Action

Defines operations that can be performed on resources.

```typescript
// Example action definitions
const actions = [
  { name: 'View', slug: 'view' },
  { name: 'Create', slug: 'create' },
  { name: 'Edit', slug: 'edit' },
  { name: 'Delete', slug: 'delete' },
];
```

### 2. Permission Management Examples

#### a) User-Based Permission

Assigning permission directly to a user:

```typescript
// Example: Give John permission to view and edit products
const permission = {
  target: 'USER',
  userId: 'john_123',
  resourceId: 'product',
  actions: ['view', 'edit'],
};
```

#### b) Role-Based Permission

Assigning permission to a role:

```typescript
// Example: Give Sales Manager role customer and order management permissions
const permission = {
  target: 'ROLE',
  roleId: 'sales_manager',
  resourceId: 'customer',
  actions: ['view', 'create', 'edit', 'delete'],
};
```

#### c) Organization-Based Permission

Assigning permission to an entire organization:

```typescript
// Example: Give Branch X permission to view orders
const permission = {
  target: 'ORGANIZATION',
  organizationId: 'branch_x',
  resourceId: 'order',
  actions: ['view'],
};
```

### 3. Permission Check Examples

#### Permission Check in Frontend

```typescript
// Permission check within component
const CanEditProduct = () => {
  const hasPermission = usePermission("product", "edit");

  if (!hasPermission) {
    return <div>You don't have permission for this operation</div>;
  }

  return <EditProductForm />;
};
```

#### Permission Check in Backend

```typescript
// Permission check in API route
export async function PUT(request: NextRequest) {
  try {
    await requirePermission('product', 'edit');
    // Continue if permission exists
  } catch (error) {
    return new NextResponse('Unauthorized', { status: 401 });
  }
}
```

### 4. API Endpoints

#### Permission Management

- `GET /api/administrations/permissions`: List all permissions
- `POST /api/administrations/permissions`: Create new permission
- `PUT /api/administrations/permissions/[id]`: Update permission
- `DELETE /api/administrations/permissions/[id]`: Delete permission

#### Resource Management

- `GET /api/administrations/resources`: List all resources
- `POST /api/administrations/resources`: Create new resource
- `PUT /api/administrations/resources/[id]`: Update resource
- `DELETE /api/administrations/resources/[id]`: Delete resource

#### Action Management

- `GET /api/administrations/actions`: List all actions
- `POST /api/administrations/actions`: Create new action
- `PUT /api/administrations/actions/[id]`: Update action
- `DELETE /api/administrations/actions/[id]`: Delete action

### 5. Example Usage Scenarios

#### Scenario 1: Sales Team Permissions

```typescript
// 1. Create Sales Role
const salesRole = await prisma.role.create({
  data: { name: 'Sales Team', description: 'Sales team members' },
});

// 2. Assign Permissions to Sales Role
const permissions = [
  {
    target: 'ROLE',
    roleId: salesRole.id,
    resourceId: 'customer',
    actions: ['view', 'create', 'edit'],
  },
  {
    target: 'ROLE',
    roleId: salesRole.id,
    resourceId: 'order',
    actions: ['view', 'create'],
  },
];

// 3. Apply Permissions
await Promise.all(permissions.map((perm) => prisma.permission.create({ data: perm })));
```

#### Scenario 2: Regional Manager Permissions

```typescript
// 1. Create Regional Manager Role
const managerRole = await prisma.role.create({
  data: { name: 'Regional Manager', description: 'Regional management team' },
});

// 2. Create Region Organization
const regionOrg = await prisma.organization.create({
  data: { name: 'East Region', code: 'EAST_001' },
});

// 3. Assign Organization-wide Permissions
const permissions = [
  {
    target: 'ORGANIZATION',
    organizationId: regionOrg.id,
    resourceId: 'sales_report',
    actions: ['view'],
  },
  {
    target: 'ORGANIZATION',
    organizationId: regionOrg.id,
    resourceId: 'performance_metrics',
    actions: ['view', 'edit'],
  },
];

await Promise.all(permissions.map((perm) => prisma.permission.create({ data: perm })));
```

## Notification System

The notification system uses Ant Design's notification component with a custom context setup:

```typescript
// types.ts
export type NotificationType = 'success' | 'error' | 'info' | 'warning';

export interface ShowNotificationFunction {
  (type: NotificationType, message: string, description?: string): void;
}

// NotificationContext.tsx
const NotificationContext = createContext<NotificationContextType | null>(null);

export const NotificationProvider = ({ children }: { children: React.ReactNode }) => {
  const [notificationApi, contextHolder] = notification.useNotification();

  const showNotification: ShowNotificationFunction = (type, message, description) => {
    notificationApi[type]({
      message,
      description,
      placement: 'topRight'
    });
  };

  return (
    <NotificationContext.Provider value={{ showNotification, notificationApi }}>
      {contextHolder}
      {children}
    </NotificationContext.Provider>
  );
};

export const useNotification = () => {
  const context = useContext(NotificationContext);
  if (!context) {
    throw new Error('useNotification must be used within a NotificationProvider');
  }
  return context;
};
```

Usage in API Client:

```typescript
// Success case (POST/PUT/DELETE)
if (['POST', 'PUT', 'DELETE'].includes(response.config.method?.toUpperCase() || '')) {
  const message =
    response.config.method?.toUpperCase() === 'DELETE'
      ? 'Deletion successful!'
      : 'Process completed successfully';

  const showNotification = window.__showNotification as ShowNotificationFunction;
  showNotification?.('success', message);
}

// Error case
const errorMessage = (error.response?.data as string) || error.message;
const showNotification = window.__showNotification as ShowNotificationFunction;
const truncatedMessage =
  errorMessage.length > 500 ? errorMessage.slice(0, 497) + '...' : errorMessage;
showNotification?.('error', 'Hata', truncatedMessage);
```

### Best Practices

1. **Consistent Usage**

   - Use the same notification system across the entire application
   - Maintain consistent message formats and durations

2. **Error Handling**

   - Always provide clear error messages
   - Include relevant error details in the description
   - Add action buttons for error recovery when applicable

3. **User Experience**

   - Keep notifications concise and informative
   - Use appropriate notification types
   - Don't overwhelm users with too many notifications
   - Consider notification stacking and positioning

4. **Integration with API Calls**

```typescript
const apiCall = async () => {
  try {
    const response = await fetch('/api/data');
    const data = await response.json();

    showNotification({
      type: 'success',
      message: 'Data Retrieved',
      description: 'Successfully fetched the requested data.',
    });

    return data;
  } catch (error) {
    showNotification({
      type: 'error',
      message: 'API Error',
      description: error.message,
    });

    throw error;
  }
};
```

### Notification Types

1. **Success Notifications**

```typescript
showNotification('success', 'Order Created', 'Order #12345 has been successfully created');
```

2. **Error Notifications**

```typescript
showNotification('error', 'API Error', 'Failed to process your request');
```

3. **Warning Notifications**

```typescript
showNotification('warning', 'Low Stock Alert', 'Product stock is below the minimum threshold');
```

4. **Info Notifications**

```typescript
showNotification('info', 'System Update', 'A system update is scheduled for tonight at 00:00');
```

### API Error Handling

```typescript
// API error interceptor
axiosInstance.interceptors.response.use(
  (response: AxiosResponse) => {
    // Success notification for POST, PUT, DELETE requests
    if (
      typeof window !== 'undefined' &&
      ['POST', 'PUT', 'DELETE'].includes(response.config.method?.toUpperCase() || '')
    ) {
      const message =
        response.config.method?.toUpperCase() === 'DELETE'
          ? 'Deletion successful!'
          : 'Process completed successfully';

      const showNotification = window.__showNotification as ShowNotificationFunction;
      showNotification?.('success', message);
    }
    return response.data;
  },
  async (error: AxiosError) => {
    if (error.response?.status === 401) {
      if (typeof window !== 'undefined') {
        await signOut({ callbackUrl: '/auth/login' });
      }
    }

    const errorMessage = (error.response?.data as string) || error.message;

    if (typeof window !== 'undefined') {
      const showNotification = window.__showNotification as ShowNotificationFunction;
      const truncatedMessage =
        errorMessage.length > 500 ? errorMessage.slice(0, 497) + '...' : errorMessage;
      showNotification?.('error', 'Hata', truncatedMessage);
    }

    throw new Error(errorMessage);
  }
);
```

### Form Validation Notifications

```typescript
const handleFormSubmit = async (values: FormValues) => {
  try {
    await validateForm(values);
    await submitForm(values);

    showNotification('success', 'Form Submitted', 'Your form has been successfully submitted');
  } catch (error) {
    if (error instanceof ValidationError) {
      showNotification('warning', 'Validation Error', error.message);
    } else {
      showNotification('error', 'Submission Error', 'Failed to submit form. Please try again');
    }
  }
};
```

### 3. Permission System Working Logic

The `lib/auth/permissions.ts` file forms the core of the permission system:

#### a) Permission Check Functions

```typescript
// 1. Basic permission check
async function checkPermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): Promise<boolean>;

// 2. Permission requirement
async function requirePermission(
  resourceSlug: string,
  actionSlug: string,
  organizationId?: string
): Promise<void>;

// 3. React hook
function usePermission(resourceSlug: string, actionSlug: string, organizationId?: string): boolean;

// 4. Higher-order component
function withPermission(
  Component: React.ComponentType<P>,
  resourceSlug: string,
  actionSlug: string
): React.FC<P>;
```

#### b) Permission Check Hierarchy

1. **System Admin Check**

   ```typescript
   if (session.user.role === 'ADMIN') return true;
   ```

2. **Direct Permission Check**

   ```typescript
   const hasDirectPermission = checkResourcePermission(
     session.user.permissions,
     resourceSlug,
     actionSlug
   );
   ```

3. **Role-Based Permission Check**

   ```typescript
   const rolePermissions = membership.role?.permissions || [];
   const hasRolePermission = checkResourcePermission(rolePermissions, resourceSlug, actionSlug);
   ```

4. **Organization Permission Check**
   ```typescript
   const organizationPermissions = membership.organization.permissions;
   return checkResourcePermission(organizationPermissions, resourceSlug, actionSlug);
   ```

### 4. Next.js 15 Route Handler Rules

#### a) Params Promise Structure

```typescript
// ✅ CORRECT USAGE
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // ... operations
}

// ❌ INCORRECT USAGE
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const { id } = params; // missing await!
  // ... operations
}
```

#### b) Route Handler Examples

```typescript
// 1. Single parameter
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // ... operations
}

// 2. Multiple parameters
export async function GET(
  request: NextRequest,
  {
    params,
  }: {
    params: Promise<{
      organizationId: string;
      userId: string;
    }>;
  }
) {
  const { organizationId, userId } = await params;
  // ... operations
}

// 3. Query parameters
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const query = searchParams.get('q');
  // ... operations
}
```

#### c) Important Notes

- `params` in route handlers is a Promise
- Use `Promise<{ id: string }>` in TypeScript definition
- Always resolve `params` with `await`
- This rule applies to all dynamic routes
- Pay attention to this rule to prevent build errors

## API Client Usage

The API client provides a type-safe way to make HTTP requests with built-in error handling and automatic notifications.

#### Basic Usage

```typescript
import { getRequest, postRequest, putRequest, deleteRequest } from '@/lib/apiClient';

// GET request
const users = await getRequest<User[]>('/users');

// POST request
const newUser = await postRequest<User>('/users', {
  name: 'John',
  email: 'john@example.com',
});

// PUT request
const updated = await putRequest<User>(`/users/${id}`, {
  name: 'Updated Name',
});

// DELETE request
const deleted = await deleteRequest<boolean>(`/users/${id}`);
```

#### Features

1. **Automatic API Prefix**

   - All requests are automatically prefixed with `/api`
   - Example: `/users` becomes `/api/users`

2. **Automatic Notifications**

   ```typescript
   // Success notifications (for POST, PUT, DELETE)
   if (['POST', 'PUT', 'DELETE'].includes(response.config.method?.toUpperCase() || '')) {
     const message =
       response.config.method?.toUpperCase() === 'DELETE'
         ? 'Deletion successful!'
         : 'Process completed successfully';
     showNotification?.('success', message);
   }

   // Error notifications
   showNotification({
     type: 'error',
     message: 'API Error',
     description: errorMessage,
   });
   ```

   - Success cases:
     - Shows for POST/PUT/DELETE operations
     - DELETE: "Deletion successful!"
     - POST/PUT: "Process completed successfully"
   - Error cases:
     - Shows "API Error" as title
     - Shows error message in description

3. **Retry Configuration**

   - 3 retry attempts for failed requests
   - Uses exponential backoff
   - Only retries on:
     - Network errors
     - 500+ server errors
   - Does not retry if response contains error data

4. **Type Safety**

   ```typescript
   interface User {
     id: number;
     name: string;
     email: string;
   }

   // TypeScript will ensure type safety
   const user = await getRequest<User>('/users/1');
   console.log(user.name); // TypeScript knows this exists
   ```

#### Error Handling Example

```typescript
try {
  const users = await getRequest<User[]>('/users');
  // Success case - for POST/PUT/DELETE, automatically shows success notification
} catch (error) {
  // Error notification is automatically shown:
  // - Shows "Hata" with truncated error message
  // - For 401, redirects to login page
  console.error('API Error:', error);
}
```

#### Request Options

```typescript
interface RequestOptions {
  headers?: Record<string, string>;
  [key: string]: any; // Additional axios request config
}

// With custom headers
const response = await getRequest<User[]>('/users', {
  headers: {
    Authorization: 'Bearer token',
    'Custom-Header': 'value',
  },
});

// With query parameters
const filtered = await getRequest<User[]>('/users', {
  role: 'admin',
  active: true,
});
```

## Installation and Development

1. Clone the repository

```bash
git clone https://github.com/yourusername/nextstarter.git
```

2. Install dependencies

```bash
npm install
```

3. Prepare the database

```bash
npx prisma generate
npx prisma db push
```

4. Start the development server

```bash
npm run dev
```

## Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

## Environment Variables and Configuration

Create a `.env` file in the project root directory and define the following variables:

```env
# Database Connection
DATABASE_URL="postgres://postgres:password@host:port/yourdbname?sslmode=disable"

# NextAuth.js Configuration
NEXTAUTH_SECRET="your-secret-key"
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SESSION_MAX_AGE=604800   # 7 days (7 * 24 * 60 * 60)
NEXTAUTH_SESSION_UPDATE_AGE=3600  # 1 hour (60 * 60)

# Super Admin Account Details
SUPER_ADMIN_MAIL="superadmin@superadmin.com"
SUPER_ADMIN_FIRSTNAME="Super"
SUPER_ADMIN_LASTNAME="Admin"
SUPER_ADMIN_PASSWORD="your-secure-password"
```

### Important Notes

1. **Database Connection**: The `DATABASE_URL` variable contains PostgreSQL connection information. Connection string format: `postgres://user:password@host:port/database?sslmode=disable`

2. **NextAuth.js Configuration**:

   - `NEXTAUTH_SECRET`: Secret key used for session security
   - `NEXTAUTH_URL`: URL where the application runs (usually `http://localhost:3000` in development)
   - `NEXTAUTH_SESSION_MAX_AGE`: Maximum session duration for session security (in seconds)
   - `NEXTAUTH_SESSION_UPDATE_AGE`: Session update duration for session security (in seconds)

3. **Super Admin Account**:
   - System automatically creates a super admin account during initial setup
   - Account details are taken from the `.env` file
   - This account has all system permissions

## Developer Guide

### 1. Commands and Scripts

```bash
# Development
npm run dev         # Start development server
npm run build       # Build project for production
npm run start       # Start production server

# Database
npm run migrate     # Create and apply Prisma migration
npm run reset-db    # Reset database
npm run seed        # Load seed data

# Code Quality
npm run lint        # Code check with ESLint
npm run format      # Format code with Prettier
```

### 2. Database Seed Process

The `prisma/seed.ts` file creates initial data:

1. **Default Resources**

   ```typescript
   // Example resources
   const defaultResources = [
     { name: 'ALL', slug: '*' },
     { name: 'ORGANIZATION', slug: 'organization' },
     { name: 'USER', slug: 'user' },
     // ...
   ];
   ```

2. **Default Actions**

   ```typescript
   const defaultActions = [
     { name: 'VIEW', slug: 'view' },
     { name: 'CREATE', slug: 'create' },
     { name: 'EDIT', slug: 'edit' },
     { name: 'DELETE', slug: 'delete' },
     { name: 'MANAGE', slug: 'manage' },
   ];
   ```

3. **Super Admin and Roles**
   - Creates super admin user
   - Defines default roles
   - Assigns basic permissions
