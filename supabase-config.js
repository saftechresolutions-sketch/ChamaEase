// ============================================
// FILE: supabase-config.js
// PURPOSE: Initialize Supabase connection
// SHARED ACROSS: All HTML pages (login, dashboard, members, etc.)
// ============================================

// IMPORTANT: Replace these with your actual Supabase credentials
// You can find them in your Supabase Project Settings -> API

const SUPABASE_URL = "https://qfihebqomluleywpgufv.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFmaWhlYnFvbWx1bGV5d3BndWZ2Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgxOTM5NDEsImV4cCI6MjA5Mzc2OTk0MX0.yKFXsCDYReshZKL9oosvm5ZwHh4GUZy1SYwFyqhDv9I";

// Create Supabase client
const supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Helper function to check if user is logged in
async function isUserAuthenticated() {
    const { data: { session }, error } = await supabaseClient.auth.getSession();
    if (error) {
        console.error("Auth check error:", error);
        return false;
    }
    return session !== null;
}

// Helper function to get current user
async function getCurrentUser() {
    const { data: { user }, error } = await supabaseClient.auth.getUser();
    if (error) return null;
    return user;
}

// Helper function to logout
async function logoutUser() {
    const { error } = await supabaseClient.auth.signOut();
    if (error) {
        console.error("Logout error:", error);
        return false;
    }
    return true;
}

// Helper function to protect pages (redirect to login if not authenticated)
async function protectPage() {
    const isAuth = await isUserAuthenticated();
    if (!isAuth) {
        window.location.href = "index.html";
        return false;
    }
    return true;
}