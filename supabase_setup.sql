-- ============================================================
-- 建筑工地考勤系统 · Supabase 建表 + 权限(RLS)脚本  v2
-- Construction Site Attendance · Supabase schema + RLS  v2
-- ============================================================
-- 使用方法 / How to run:
--   1. 打开 Supabase 控制台 → 你的项目 → 左侧 "SQL Editor"
--   2. 点 "New query",把本文件全部内容复制粘贴进去
--   3. 点 "Run"(Ctrl+Enter),看到 "Success" 即完成
-- 本脚本可重复运行(幂等),已经建过库的项目再跑一次即可升级到 v2,
-- 不会清空数据 / Safe to re-run; upgrades an existing DB to v2 without data loss.
-- ============================================================


-- ---------- 1. 建表 Tables ----------

-- 工地 Sites
create table if not exists public.sites (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_at timestamptz not null default now()
);

-- 员工 Employees
create table if not exists public.employees (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  nric       text,                       -- 身份证/护照号 NRIC / Passport
  trade      text,                       -- 工种 carpenter / barbender / ksk / other
  has_cidb   boolean not null default false,   -- 是否有 CIDB 证件 Has CIDB card
  site_id    uuid references public.sites(id) on delete set null,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.employees add column if not exists nric     text;
alter table public.employees add column if not exists trade    text;
alter table public.employees add column if not exists has_cidb boolean not null default false;

-- 用户资料 Profiles(角色 role + 称呼 name)
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  name       text,                       -- 称呼 display name
  role       text not null default 'manager' check (role in ('manager', 'hr')),
  site_id    uuid references public.sites(id) on delete set null,  -- 旧字段,保留兼容
  created_at timestamptz not null default now()
);
alter table public.profiles add column if not exists name text;

-- 负责人 ↔ 工地(多对多:一个负责人可管理多个工地)
-- Manager ↔ Site (many-to-many: a manager can run several sites)
create table if not exists public.manager_sites (
  profile_id uuid not null references public.profiles(id) on delete cascade,
  site_id    uuid not null references public.sites(id)    on delete cascade,
  primary key (profile_id, site_id)
);

-- 考勤 Attendance(每位员工每天一条,可覆盖修改)
create table if not exists public.attendance (
  id          uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  site_id     uuid not null references public.sites(id) on delete cascade,
  date        date not null,
  status      text not null check (status in ('present', 'absent')),
  hours       smallint,                          -- 当天总工时(含OT)0/8/10/12
  ot_hours    smallint not null default 0,       -- 其中的加班时数 OT hours 0/2
  marked_by   uuid references auth.users(id),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (employee_id, date)
);
alter table public.attendance add column if not exists hours    smallint;
alter table public.attendance add column if not exists ot_hours smallint not null default 0;

create index if not exists attendance_site_date_idx on public.attendance (site_id, date);
create index if not exists attendance_date_idx       on public.attendance (date);
create index if not exists employees_site_idx        on public.employees (site_id);
create index if not exists manager_sites_profile_idx on public.manager_sites (profile_id);

-- 把旧的"单一工地"分配迁移到新表(只跑一次有效果)
-- Migrate the old single-site assignment into manager_sites
insert into public.manager_sites (profile_id, site_id)
select id, site_id from public.profiles
where role = 'manager' and site_id is not null
on conflict do nothing;


-- ---------- 2. 辅助函数 Helper functions ----------
-- SECURITY DEFINER:以所有者身份运行、绕过 RLS,避免策略递归(Supabase 官方写法)。

create or replace function public.my_role()
returns text language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid();
$$;

-- 当前登录负责人管理的所有工地 id / all site ids the current manager runs
create or replace function public.my_site_ids()
returns setof uuid language sql stable security definer set search_path = public as $$
  select site_id from public.manager_sites where profile_id = auth.uid();
$$;


-- ---------- 3. 新用户自动建资料(带称呼)New user → profile ----------
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, role, name)
  values (new.id, new.email, 'manager', new.raw_user_meta_data->>'name')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ---------- 4. 开启行级安全 Enable RLS ----------
alter table public.sites         enable row level security;
alter table public.employees     enable row level security;
alter table public.profiles      enable row level security;
alter table public.manager_sites enable row level security;
alter table public.attendance    enable row level security;


-- ---------- 5. 权限策略 Policies ----------

-- ===== profiles =====
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select using (id = auth.uid() or public.my_role() = 'hr');

drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles
  for update using (public.my_role() = 'hr') with check (public.my_role() = 'hr');

-- ===== sites =====
drop policy if exists sites_select on public.sites;
create policy sites_select on public.sites
  for select using (public.my_role() = 'hr' or id in (select public.my_site_ids()));

drop policy if exists sites_insert on public.sites;
create policy sites_insert on public.sites
  for insert with check (public.my_role() = 'hr');
drop policy if exists sites_update on public.sites;
create policy sites_update on public.sites
  for update using (public.my_role() = 'hr') with check (public.my_role() = 'hr');
drop policy if exists sites_delete on public.sites;
create policy sites_delete on public.sites
  for delete using (public.my_role() = 'hr');

-- ===== employees =====
drop policy if exists employees_select on public.employees;
create policy employees_select on public.employees
  for select using (public.my_role() = 'hr' or site_id in (select public.my_site_ids()));

drop policy if exists employees_insert on public.employees;
create policy employees_insert on public.employees
  for insert with check (public.my_role() = 'hr');
drop policy if exists employees_update on public.employees;
create policy employees_update on public.employees
  for update using (public.my_role() = 'hr') with check (public.my_role() = 'hr');
drop policy if exists employees_delete on public.employees;
create policy employees_delete on public.employees
  for delete using (public.my_role() = 'hr');

-- ===== manager_sites(谁管哪些工地)=====
drop policy if exists manager_sites_select on public.manager_sites;
create policy manager_sites_select on public.manager_sites
  for select using (public.my_role() = 'hr' or profile_id = auth.uid());
drop policy if exists manager_sites_insert on public.manager_sites;
create policy manager_sites_insert on public.manager_sites
  for insert with check (public.my_role() = 'hr');
drop policy if exists manager_sites_delete on public.manager_sites;
create policy manager_sites_delete on public.manager_sites
  for delete using (public.my_role() = 'hr');

-- ===== attendance =====
drop policy if exists attendance_select on public.attendance;
create policy attendance_select on public.attendance
  for select using (public.my_role() = 'hr' or site_id in (select public.my_site_ids()));

drop policy if exists attendance_insert on public.attendance;
create policy attendance_insert on public.attendance
  for insert with check (public.my_role() = 'hr' or site_id in (select public.my_site_ids()));

drop policy if exists attendance_update on public.attendance;
create policy attendance_update on public.attendance
  for update using      (public.my_role() = 'hr' or site_id in (select public.my_site_ids()))
              with check (public.my_role() = 'hr' or site_id in (select public.my_site_ids()));

drop policy if exists attendance_delete on public.attendance;
create policy attendance_delete on public.attendance
  for delete using (public.my_role() = 'hr' or site_id in (select public.my_site_ids()));


-- ---------- 6. 刷新缓存 Reload schema cache ----------
notify pgrst, 'reload schema';

-- ============================================================
-- 完成!注册账号后运行下面这行把自己设为人事部(换成你的邮箱):
-- Done! After registering, make yourself HR (replace email):
--   update public.profiles set role = 'hr' where email = '你的邮箱@example.com';
-- ============================================================
