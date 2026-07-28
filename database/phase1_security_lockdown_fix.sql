-- ============================================================
-- ChamaEase — Phase 1 Security Lockdown — RECURSION FIX
-- ============================================================
-- Run this AFTER phase1_security_lockdown.sql if you hit:
--   "infinite recursion detected in policy for relation admins"
--
-- Why it happened: the policy on `admins` checked membership by
-- querying `admins` itself. But RLS applies to that inner query
-- too, which re-runs the same policy, which queries `admins`
-- again... forever. Same problem existed implicitly for
-- members/monthly_records/contributions, since their policies
-- also queried `admins` directly.
--
-- Fix: wrap the admin check in a SECURITY DEFINER function. That
-- runs with the function owner's privileges, which bypasses RLS
-- for the query inside it — breaking the recursive loop — while
-- everything calling the function still goes through RLS as
-- normal.
-- ============================================================


-- 1. The admin-check function (bypasses RLS internally, safe) ---
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


-- 2. Fix the `admins` table's own policy -------------------------
drop policy if exists "admins can view admins" on public.admins;
create policy "admins can view admins"
    on public.admins
    for select
    using (public.is_admin());


-- 3. Fix `members` ------------------------------------------------
drop policy if exists "admins full access to members" on public.members;
create policy "admins full access to members"
    on public.members
    for all
    using (public.is_admin())
    with check (public.is_admin());


-- 4. Fix `monthly_records` -----------------------------------------
drop policy if exists "admins full access to monthly_records" on public.monthly_records;
create policy "admins full access to monthly_records"
    on public.monthly_records
    for all
    using (public.is_admin())
    with check (public.is_admin());


-- 5. Fix `contributions`, only if it exists ------------------------
do $$
begin
    if exists (select 1 from information_schema.tables
               where table_schema = 'public' and table_name = 'contributions') then
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
-- After running this, refresh the app and log in again — the
-- "infinite recursion" error should be gone.
--
-- Verify with:
--   select public.is_admin();   -- run this while logged in via
--                                -- the SQL editor's "Run as" user,
--                                -- or just retest in the app.
-- ============================================================
