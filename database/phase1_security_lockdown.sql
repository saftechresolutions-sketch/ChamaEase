-- ============================================================
-- ChamaEase — Phase 1 Security Lockdown
-- ============================================================
-- Run this ONCE in: Supabase Dashboard > SQL Editor > New query
--
-- What this does:
--   1. Creates an `admins` table that says who is allowed to
--      touch chama data (linked to Supabase Auth users).
--   2. Adds every existing user as an admin (safe today, since
--      signup is now closed in the app — see note at the bottom).
--   3. Adds a SECURITY DEFINER helper function, is_admin(), used
--      by every policy below to check admin membership without
--      triggering RLS recursion on the admins table itself.
--   4. Turns on Row Level Security (RLS) for `members` and
--      `monthly_records`, and adds policies so ONLY people listed
--      in `admins` can read/write/delete those tables.
--
-- Why this matters: right now the app's "you must be logged in"
-- check happens only in the browser (protectPage() in
-- supabase-config.js). Anyone who knows the project URL + anon key
-- (both of which are public/visible in the page source, by design)
-- can call the Supabase REST API directly, bypassing the app
-- entirely — UNLESS the database itself refuses the request. RLS
-- is that refusal. Without it, the app's UI restrictions are only
-- a convenience, not a security boundary.
-- ============================================================


-- 1. Table of authorized admins ---------------------------------
create table if not exists public.admins (
    user_id uuid primary key references auth.users(id) on delete cascade,
    created_at timestamptz not null default now()
);

alter table public.admins enable row level security;


-- 2. Admin-check helper (SECURITY DEFINER avoids RLS recursion) --
-- IMPORTANT: policies must call this function rather than querying
-- `public.admins` directly. A policy on `admins` that queries
-- `admins` inline causes "infinite recursion detected in policy
-- for relation admins", because RLS re-applies to that inner query
-- too. SECURITY DEFINER runs the function's inner query with the
-- function owner's privileges, bypassing RLS for that one lookup.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
    select exists (
        select 1 from public.admins a where a.user_id = auth.uid()
    );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to authenticated;

drop policy if exists "admins can view admins" on public.admins;
create policy "admins can view admins"
    on public.admins
    for select
    using (public.is_admin());


-- 3. Seed: make every current user an admin ----------------------
-- Safe to run more than once (ON CONFLICT DO NOTHING).
-- Anyone who signed up before you closed public registration will
-- be included here — review the list below before/after running
-- this and remove anyone who shouldn't have access:
--   select id, email from auth.users;
insert into public.admins (user_id)
select id from auth.users
on conflict (user_id) do nothing;


-- 4. Lock down `members` -----------------------------------------
alter table public.members enable row level security;

drop policy if exists "admins full access to members" on public.members;
create policy "admins full access to members"
    on public.members
    for all
    using (public.is_admin())
    with check (public.is_admin());


-- 5. Lock down `monthly_records` -----------------------------------
alter table public.monthly_records enable row level security;

drop policy if exists "admins full access to monthly_records" on public.monthly_records;
create policy "admins full access to monthly_records"
    on public.monthly_records
    for all
    using (public.is_admin())
    with check (public.is_admin());


-- 6. Lock down `contributions`, only if it still exists -----------
-- (Legacy table used by statistics.html / contribution-history.html.
--  Harmless no-op if you've already removed it.)
do $$
begin
    if exists (select 1 from information_schema.tables
               where table_schema = 'public' and table_name = 'contributions') then
        execute 'alter table public.contributions enable row level security';

        execute 'drop policy if exists "admins full access to contributions" on public.contributions';
        execute $policy$
            create policy "admins full access to contributions"
            on public.contributions
            for all
            using (public.is_admin())
            with check (public.is_admin())
        $policy$;
    end if;
end $$;


-- ============================================================
-- AFTER running this script, also do the following manually —
-- they can't be done via SQL:
--
-- A) Disable public signup (belt-and-suspenders — the app's
--    "Create account" link is already removed, but someone could
--    still call the signUp() API directly unless you also flip
--    this server-side):
--      Supabase Dashboard > Authentication > Sign In / Providers
--      > Email > turn OFF "Allow new users to sign up"
--
-- B) To add a new admin later (e.g. after creating their account
--    in Authentication > Users), run:
--      insert into public.admins (user_id)
--      select id from auth.users where email = 'someone@example.com';
--
-- C) To verify RLS is actually active, run:
--      select tablename, rowsecurity from pg_tables
--      where schemaname = 'public'
--      and tablename in ('members', 'monthly_records', 'contributions');
--    Every row should show rowsecurity = true.
-- ============================================================
