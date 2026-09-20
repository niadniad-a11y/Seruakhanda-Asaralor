
-- ============================================================
-- SERUAKANDA ASHA ALO FOUNDATION
-- SUPABASE DATABASE SETUP
-- ============================================================
-- Run this whole file in Supabase Dashboard -> SQL Editor.
-- Then create your Admin Auth user in Authentication -> Users.
-- After creating that user, insert their UUID into admin_users.
-- ============================================================

create extension if not exists pgcrypto;

-- ------------------------------------------------------------
-- 1) Admin users
-- ------------------------------------------------------------
create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;

drop policy if exists "admin_users_select_self" on public.admin_users;
create policy "admin_users_select_self"
on public.admin_users
for select
to authenticated
using (user_id = auth.uid());

-- Helper used by RLS and RPC functions.
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1
    from public.admin_users
    where user_id = auth.uid()
  );
$$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- ------------------------------------------------------------
-- 2) Member profiles
-- ------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  mobile text not null unique,
  display_email text,
  auth_email text not null,
  address text,
  status text not null default 'Active'
    check (status in ('Active','Removed')),
  role text not null default 'Member'
    check (role in ('Member')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_public_read" on public.profiles;
create policy "profiles_public_read"
on public.profiles
for select
to anon, authenticated
using (true);

drop policy if exists "profiles_insert_self" on public.profiles;
create policy "profiles_insert_self"
on public.profiles
for insert
to authenticated
with check (
  id = auth.uid()
  and role = 'Member'
);

drop policy if exists "profiles_update_self_or_admin" on public.profiles;
create policy "profiles_update_self_or_admin"
on public.profiles
for update
to authenticated
using (
  id = auth.uid() or public.is_admin()
)
with check (
  (id = auth.uid() and role = 'Member')
  or public.is_admin()
);

-- ------------------------------------------------------------
-- 3) Shared website state
--    Settings, projects, notices, notifications, audit logs.
--    Members can read it; only Admin can write it.
-- ------------------------------------------------------------
create table if not exists public.foundation_state (
  id bigint primary key check (id = 1),
  settings jsonb not null default '{}'::jsonb,
  announcements jsonb not null default '[]'::jsonb,
  projects jsonb not null default '[]'::jsonb,
  notifications jsonb not null default '[]'::jsonb,
  audit_logs jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.foundation_state enable row level security;

drop policy if exists "foundation_state_public_read" on public.foundation_state;
create policy "foundation_state_public_read"
on public.foundation_state
for select
to anon, authenticated
using (true);

-- No direct INSERT/UPDATE policy is intentionally created.
-- The save RPC below is Admin-only.

insert into public.foundation_state (
  id,
  settings,
  announcements,
  projects,
  notifications,
  audit_logs
)
values (
  1,
  jsonb_build_object(
    'orgName', 'সেরুয়াকান্দা আশা আলো ফাউন্ডেশন',
    'tagline', 'স্বেচ্ছায় সহযোগিতা • সম্মিলিত উন্নয়ন • মানবিক সহায়তা',
    'logoUrl', '',
    'bkashNumber', '',
    'bkashAccountType', 'Personal',
    'contactNumber', '',
    'email', '',
    'address', '',
    'facebookUrl', '',
    'about', 'সেরুয়াকান্দা আশা আলো ফাউন্ডেশনের লক্ষ্য হলো স্বেচ্ছাসেবী উদ্যোগের মাধ্যমে মানুষের পাশে দাঁড়ানো এবং সম্মিলিত উন্নয়নে কাজ করা।',
    'privacyPublicNames', false,
    'primaryColor', '#15803d',
    'accentColor', '#0ea5e9',
    'textColor', '#0f172a',
    'backgroundColor', '#f8fafc',
    'footerText', 'সেরুয়াকান্দা আশা আলো ফাউন্ডেশন — সম্মিলিত উন্নয়নের প্রত্যয়ে',
    'media', '[]'::jsonb
  ),
  '[]'::jsonb,
  '[]'::jsonb,
  '[]'::jsonb,
  '[]'::jsonb
)
on conflict (id) do nothing;

create or replace function public.save_foundation_state(p_state jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'Admin permission required';
  end if;

  update public.foundation_state
  set
    settings = coalesce(p_state->'settings', '{}'::jsonb),
    announcements = coalesce(p_state->'announcements', '[]'::jsonb),
    projects = coalesce(p_state->'projects', '[]'::jsonb),
    notifications = coalesce(p_state->'notifications', '[]'::jsonb),
    audit_logs = coalesce(p_state->'auditLogs', '[]'::jsonb),
    updated_at = now()
  where id = 1;
end;
$$;

grant execute on function public.save_foundation_state(jsonb)
to authenticated;

-- ------------------------------------------------------------
-- 4) Contributions
-- ------------------------------------------------------------
create table if not exists public.contributions (
  id text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  member_name text not null,
  mobile text,
  amount numeric(12,2) not null check (amount >= 0),
  txn_id text not null unique,
  date text not null,
  status text not null default 'pending'
    check (status in ('pending','verified','rejected')),
  note text,
  created_at timestamptz not null default now()
);

alter table public.contributions enable row level security;

drop policy if exists "contributions_public_read" on public.contributions;
create policy "contributions_public_read"
on public.contributions
for select
to anon, authenticated
using (true);

drop policy if exists "contributions_insert_self" on public.contributions;
create policy "contributions_insert_self"
on public.contributions
for insert
to authenticated
with check (user_id = auth.uid());

create or replace function public.submit_contribution(p_contribution jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
begin
  if uid is null then
    raise exception 'Login required';
  end if;

  insert into public.contributions (
    id, user_id, member_name, mobile, amount, txn_id, date, status, note
  )
  values (
    p_contribution->>'id',
    uid,
    p_contribution->>'member_name',
    p_contribution->>'mobile',
    coalesce((p_contribution->>'amount')::numeric, 0),
    upper(p_contribution->>'txn_id'),
    p_contribution->>'date',
    'pending',
    p_contribution->>'note'
  );

  update public.foundation_state
  set notifications =
    jsonb_build_array(
      jsonb_build_object(
        'id', 'notif_' || gen_random_uuid()::text,
        'title', 'নতুন সহযোগিতা জমা হয়েছে',
        'message',
          (p_contribution->>'amount') || ' টাকা সহযোগিতার TrxID ' ||
          upper(p_contribution->>'txn_id') ||
          ' verification-এর অপেক্ষায় আছে।',
        'date', 'এখনই'
      )
    ) || coalesce(notifications, '[]'::jsonb),
    updated_at = now()
  where id = 1;
end;
$$;

grant execute on function public.submit_contribution(jsonb)
to authenticated;

create or replace function public.admin_verify_contribution(
  p_id text,
  p_status text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'Admin permission required';
  end if;

  if p_status not in ('pending','verified','rejected') then
    raise exception 'Invalid contribution status';
  end if;

  update public.contributions
  set status = p_status
  where id = p_id;
end;
$$;

grant execute on function public.admin_verify_contribution(text,text)
to authenticated;

-- ------------------------------------------------------------
-- 5) Posts
-- ------------------------------------------------------------
create table if not exists public.posts (
  id text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  author text not null,
  author_role text not null default 'সদস্য',
  title text not null,
  content text not null,
  likes integer not null default 0,
  status text not null default 'approved',
  date text not null,
  comments jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.posts enable row level security;

drop policy if exists "posts_public_read" on public.posts;
create policy "posts_public_read"
on public.posts
for select
to anon, authenticated
using (true);

create or replace function public.submit_post(p_post jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
begin
  if uid is null then
    raise exception 'Login required';
  end if;

  insert into public.posts (
    id, user_id, author, author_role, title, content,
    likes, status, date, comments
  )
  values (
    p_post->>'id',
    uid,
    p_post->>'author',
    coalesce(p_post->>'author_role', 'সদস্য'),
    p_post->>'title',
    p_post->>'content',
    0,
    'approved',
    p_post->>'date',
    '[]'::jsonb
  );
end;
$$;

grant execute on function public.submit_post(jsonb)
to authenticated;

create or replace function public.like_post(p_post_id text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.posts
  set likes = likes + 1
  where id = p_post_id;
end;
$$;

grant execute on function public.like_post(text)
to authenticated, anon;

create or replace function public.add_post_comment(
  p_post_id text,
  p_comment jsonb
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Login required';
  end if;

  update public.posts
  set comments =
    coalesce(comments, '[]'::jsonb) || jsonb_build_array(p_comment)
  where id = p_post_id;
end;
$$;

grant execute on function public.add_post_comment(text,jsonb)
to authenticated;

-- ------------------------------------------------------------
-- 6) Admin member status
-- ------------------------------------------------------------
create or replace function public.admin_set_member_status(
  p_user_id uuid,
  p_status text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then
    raise exception 'Admin permission required';
  end if;

  if p_status not in ('Active','Removed') then
    raise exception 'Invalid member status';
  end if;

  update public.profiles
  set status = p_status
  where id = p_user_id;
end;
$$;

grant execute on function public.admin_set_member_status(uuid,text)
to authenticated;

-- ------------------------------------------------------------
-- 7) Useful grants
-- ------------------------------------------------------------
grant select on public.foundation_state to anon, authenticated;
grant select on public.profiles to anon, authenticated;
grant select on public.contributions to anon, authenticated;
grant select on public.posts to anon, authenticated;

-- ------------------------------------------------------------
-- DONE
-- ------------------------------------------------------------
-- IMPORTANT:
-- A) In Supabase Authentication settings, turn OFF email confirmation
--    if you want registration to immediately log in.
-- B) Create one Admin user under Authentication -> Users.
-- C) Copy that Auth user's UUID and run:
--
-- insert into public.admin_users(user_id)
-- values ('PASTE-ADMIN-USER-UUID-HERE');
--
-- D) Put your Supabase Project URL and Publishable Key into the HTML.
-- E) Never put sb_secret/service_role in the HTML.
