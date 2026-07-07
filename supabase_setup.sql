-- ============================================================
-- 建筑工地考勤系统 · Supabase 建表 + 权限(RLS)脚本
-- ============================================================
-- 使用方法:
--   1. 打开 Supabase 控制台 (https://supabase.com/dashboard)
--   2. 选中你的项目 → 左侧菜单点 "SQL Editor"
--   3. 点 "New query",把本文件全部内容复制粘贴进去
--   4. 点右下角 "Run"(或按 Ctrl+Enter),看到 "Success" 即完成
-- 本脚本可重复运行(已做幂等处理),重跑不会报错、不会清空数据。
-- ============================================================


-- ---------- 1. 建表 ----------

-- 工地
create table if not exists public.sites (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_at timestamptz not null default now()
);

-- 员工
create table if not exists public.employees (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  site_id    uuid references public.sites(id) on delete set null,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

-- 用户资料(角色 + 所属工地)。id 与 Supabase 登录用户一一对应。
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text,
  role       text not null default 'manager' check (role in ('manager', 'hr')),
  site_id    uuid references public.sites(id) on delete set null,
  created_at timestamptz not null default now()
);

-- 考勤记录。每位员工每天最多一条(可覆盖修改)。
create table if not exists public.attendance (
  id          uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  site_id     uuid not null references public.sites(id) on delete cascade,
  date        date not null,
  status      text not null check (status in ('present', 'absent')),
  marked_by   uuid references auth.users(id),
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (employee_id, date)
);

create index if not exists attendance_site_date_idx on public.attendance (site_id, date);
create index if not exists attendance_date_idx      on public.attendance (date);
create index if not exists employees_site_idx        on public.employees (site_id);


-- ---------- 2. 辅助函数 ----------
-- SECURITY DEFINER:以函数所有者身份运行、绕过 RLS,避免 profiles 策略自我递归。
-- 这是 Supabase 官方推荐的写法。

create or replace function public.my_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid();
$$;

create or replace function public.my_site()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select site_id from public.profiles where id = auth.uid();
$$;


-- ---------- 3. 新用户自动建资料 ----------
-- 有人在 App 里注册(写入 auth.users)时,自动在 profiles 建一行,
-- 默认角色 manager、未分配工地。未分配工地前看不到任何数据(安全)。

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'manager')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ---------- 4. 开启行级安全(RLS)----------

alter table public.sites      enable row level security;
alter table public.employees  enable row level security;
alter table public.profiles   enable row level security;
alter table public.attendance enable row level security;


-- ---------- 5. 权限策略 ----------
-- 先删除同名策略再创建,保证脚本可重复运行。

-- ===== profiles(用户资料)=====
-- 读:自己那行,或人事部可读全部(用于账号管理)
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select using (id = auth.uid() or public.my_role() = 'hr');

-- 改:只有人事部能改(给负责人分配工地 / 调整角色);负责人不能自改角色和工地
drop policy if exists profiles_update on public.profiles;
create policy profiles_update on public.profiles
  for update using (public.my_role() = 'hr') with check (public.my_role() = 'hr');
-- 注:插入由上面的触发器完成(SECURITY DEFINER 绕过 RLS),所以不需要 insert 策略。


-- ===== sites(工地)=====
-- 读:人事部看全部;负责人只看自己那个工地
drop policy if exists sites_select on public.sites;
create policy sites_select on public.sites
  for select using (public.my_role() = 'hr' or id = public.my_site());

-- 增删改:只有人事部
drop policy if exists sites_insert on public.sites;
create policy sites_insert on public.sites
  for insert with check (public.my_role() = 'hr');

drop policy if exists sites_update on public.sites;
create policy sites_update on public.sites
  for update using (public.my_role() = 'hr') with check (public.my_role() = 'hr');

drop policy if exists sites_delete on public.sites;
create policy sites_delete on public.sites
  for delete using (public.my_role() = 'hr');


-- ===== employees(员工)=====
-- 读:人事部看全部;负责人只看本工地员工
drop policy if exists employees_select on public.employees;
create policy employees_select on public.employees
  for select using (public.my_role() = 'hr' or site_id = public.my_site());

-- 增删改:只有人事部
drop policy if exists employees_insert on public.employees;
create policy employees_insert on public.employees
  for insert with check (public.my_role() = 'hr');

drop policy if exists employees_update on public.employees;
create policy employees_update on public.employees
  for update using (public.my_role() = 'hr') with check (public.my_role() = 'hr');

drop policy if exists employees_delete on public.employees;
create policy employees_delete on public.employees
  for delete using (public.my_role() = 'hr');


-- ===== attendance(考勤)=====
-- 读:人事部看全部;负责人只看本工地
drop policy if exists attendance_select on public.attendance;
create policy attendance_select on public.attendance
  for select using (public.my_role() = 'hr' or site_id = public.my_site());

-- 写(新增):人事部,或负责人且只能写自己工地(with check 防止伪造他人工地)
drop policy if exists attendance_insert on public.attendance;
create policy attendance_insert on public.attendance
  for insert with check (public.my_role() = 'hr' or site_id = public.my_site());

-- 写(修改):同上
drop policy if exists attendance_update on public.attendance;
create policy attendance_update on public.attendance
  for update
  using      (public.my_role() = 'hr' or site_id = public.my_site())
  with check (public.my_role() = 'hr' or site_id = public.my_site());

-- 删除:人事部,或本工地负责人
drop policy if exists attendance_delete on public.attendance;
create policy attendance_delete on public.attendance
  for delete using (public.my_role() = 'hr' or site_id = public.my_site());


-- ============================================================
-- 完成!接下来:
--   · 到 App 注册你的账号后,回到这里运行下面这行把自己设为人事部
--     (把邮箱换成你注册用的邮箱):
--
--     update public.profiles set role = 'hr' where email = '你的邮箱@example.com';
--
-- ============================================================
