// Type definitions
interface UserRow {
    id: number;
    username: string;
    password_hash: string;
    created_at: string;
}

interface ChannelRow {
    id: number;
    name: string;
}

interface MessageRow {
    id: number;
    channel: string;
    user: string;
    message: string;
    fileUrl?: string | null;
    fileName?: string | null;
    timestamp: string;
}
