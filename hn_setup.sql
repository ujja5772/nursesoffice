-- Nurse's Office 보건실 앱 (hn_ 표) : Supabase "영어 아카이브" 프로젝트용
create table if not exists public.hn_settings (
  id int primary key default 1 check (id = 1),
  pw_hash text,
  numbers jsonb not null default '{}'::jsonb,
  student_pin text
);
alter table public.hn_settings add column if not exists student_pin text;
insert into public.hn_settings (id) values (1) on conflict do nothing;

-- 예전 버전 함수가 있으면 정리 (학생 핀 추가로 인자가 바뀜)
drop function if exists public.hn_submit_card(int,int,text,text,text,text[],text,text,jsonb);
drop function if exists public.hn_my_card(int,int);
drop function if exists public.hn_get_delivery(int,int,text);
drop function if exists public.hn_submit_reply(uuid,int,int,text,text[],text,jsonb);

create table if not exists public.hn_cards (
  id uuid primary key default gen_random_uuid(),
  class_no int not null check (class_no between 1 and 4),
  student_no int not null,
  student_name text not null,
  avatar text,
  guest_name text,
  symptoms text[] not null default '{}',
  feel text,
  extra text,
  card_lines jsonb not null default '[]'::jsonb,
  assigned_no int,
  assigned_name text,
  assigned_at timestamptz,
  reply_no int,
  reply_name text,
  reply_meds text[],
  reply_advice text,
  reply_lines jsonb,
  hidden boolean not null default false,
  featured boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (class_no, student_no)
);

create table if not exists public.hn_scores (
  id bigserial primary key,
  class_no int not null check (class_no between 1 and 4),
  names text not null,
  score int not null default 0,
  cured int not null default 0,
  total int not null default 0,
  created_at timestamptz not null default now()
);

alter table public.hn_settings enable row level security;
alter table public.hn_cards enable row level security;
alter table public.hn_scores enable row level security;

create or replace function public.hn_pw_ok(p_pw text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select coalesce((select pw_hash is not null and pw_hash = crypt(p_pw, pw_hash) from hn_settings where id = 1), false);
$$;
revoke execute on function public.hn_pw_ok(text) from public, anon, authenticated;

-- 학생 핀: 선생님이 정하지 않았으면(null) 누구나 통과
create or replace function public.hn_pin_ok(p_pin text) returns boolean
language sql security definer set search_path = public as $$
  select coalesce((select student_pin is null or student_pin = coalesce(p_pin,'') from hn_settings where id = 1), true);
$$;
revoke execute on function public.hn_pin_ok(text) from public, anon, authenticated;

create or replace function public.hn_check_pin(p_pin text) returns boolean
language sql security definer set search_path = public as $$ select hn_pin_ok(p_pin); $$;

create or replace function public.hn_set_student_pin(p_pw text, p_pin text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  update hn_settings set student_pin = nullif(left(trim(coalesce(p_pin,'')),12),'') where id = 1;
  return true;
end $$;

create or replace function public.hn_has_pw() returns boolean
language sql security definer set search_path = public as $$
  select pw_hash is not null from hn_settings where id = 1;
$$;

create or replace function public.hn_setup_pw(p_new text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if length(coalesce(p_new,'')) < 4 then return false; end if;
  update hn_settings set pw_hash = crypt(p_new, gen_salt('bf')) where id = 1 and pw_hash is null;
  return found;
end $$;

create or replace function public.hn_teacher_login(p_pw text) returns boolean
language sql security definer set search_path = public as $$ select hn_pw_ok(p_pw); $$;

create or replace function public.hn_change_pw(p_old text, p_new text) returns boolean
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not hn_pw_ok(p_old) or length(coalesce(p_new,'')) < 4 then return false; end if;
  update hn_settings set pw_hash = crypt(p_new, gen_salt('bf')) where id = 1;
  return true;
end $$;

create or replace function public.hn_get_numbers(p_class int) returns text
language sql security definer set search_path = public as $$
  select numbers->>(p_class::text) from hn_settings where id = 1;
$$;

create or replace function public.hn_set_numbers(p_pw text, p_class int, p_numbers text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  update hn_settings set numbers = jsonb_set(numbers, array[p_class::text], to_jsonb(left(coalesce(p_numbers,''),300))) where id = 1;
  return true;
end $$;

-- 답장(처방) 표: 문진표 하나에 답장 여러 개 (최대 5개). lines 가 null 이면 '쓰는 중'
-- 학생 개인 비밀번호: 처음 들어올 때 학생이 직접 정해요 (암호화 저장)
create table if not exists public.hn_students (
  class_no int not null check (class_no between 1 and 4),
  student_no int not null,
  pin_hash text not null,
  created_at timestamptz not null default now(),
  last_at timestamptz,
  primary key (class_no, student_no)
);
alter table public.hn_students enable row level security;

create or replace function public.hn_auth(p_class int, p_no int, p_pin text) returns boolean
language sql security definer set search_path = public, extensions as $$
  select coalesce((select pin_hash = crypt(coalesce(p_pin,''), pin_hash) from hn_students where class_no = p_class and student_no = p_no), false);
$$;
revoke execute on function public.hn_auth(int,int,text) from public, anon, authenticated;

-- 로그인: 'new' = 아직 비밀번호 없음(정하기), 'ok', 'wrong'
create or replace function public.hn_student_login(p_class int, p_no int, p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from hn_students where class_no = p_class and student_no = p_no) then return 'new'; end if;
  if hn_auth(p_class, p_no, p_pin) then
    update hn_students set last_at = now() where class_no = p_class and student_no = p_no;
    return 'ok';
  end if;
  return 'wrong';
end $$;

create or replace function public.hn_student_register(p_class int, p_no int, p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
  if p_class not between 1 and 4 or p_no is null or p_no not between 1 and 199 then return 'bad'; end if;
  if length(coalesce(p_pin,'')) not between 4 and 12 then return 'bad'; end if;
  insert into hn_students (class_no, student_no, pin_hash, last_at)
  values (p_class, p_no, crypt(p_pin, gen_salt('bf')), now())
  on conflict do nothing;
  if found then return 'ok'; end if;
  return 'exists';
end $$;

create table if not exists public.hn_replies (
  id bigserial primary key,
  card_id uuid not null references public.hn_cards(id) on delete cascade,
  class_no int not null,
  reply_no int not null,
  meds text[],
  lines jsonb,
  started_at timestamptz not null default now(),
  done_at timestamptz,
  unique (card_id, reply_no)
);
create index if not exists hn_replies_class on public.hn_replies(class_no) where lines is not null;
alter table public.hn_replies add column if not exists best boolean not null default false;
alter table public.hn_replies enable row level security;

create or replace function public.hn_submit_card(
  p_pin text, p_class int, p_no int, p_name text, p_avatar text, p_guest text,
  p_symptoms text[], p_feel text, p_extra text, p_lines jsonb
) returns text
language plpgsql security definer set search_path = public as $$
declare r hn_cards;
begin
  if not hn_auth(p_class, p_no, p_pin) then return 'pin'; end if;
  if p_class not between 1 and 4 or p_no is null or length(coalesce(p_name,'')) = 0 then return 'bad'; end if;
  if jsonb_array_length(coalesce(p_lines,'[]'::jsonb)) > 10 or length(p_lines::text) > 1000 then return 'bad'; end if;
  select * into r from hn_cards where class_no = p_class and student_no = p_no;
  if found and exists (select 1 from hn_replies where card_id = r.id and lines is not null) then return 'locked'; end if;
  insert into hn_cards (class_no, student_no, student_name, avatar, guest_name, symptoms, feel, extra, card_lines)
  values (p_class, p_no, left(p_name,20), left(p_avatar,30), left(p_guest,20), p_symptoms[1:4], left(p_feel,20), left(p_extra,200), p_lines)
  on conflict (class_no, student_no) do update set
    student_name = excluded.student_name, avatar = excluded.avatar, guest_name = excluded.guest_name,
    symptoms = excluded.symptoms, feel = excluded.feel, extra = excluded.extra, card_lines = excluded.card_lines,
    updated_at = now();
  delete from hn_replies where card_id = (select id from hn_cards where class_no = p_class and student_no = p_no) and lines is null;
  return 'ok';
end $$;

-- 내 문진표 + 받은 답장들 + 내가 쓴 답장(도장)
create or replace function public.hn_my_card(p_pin text, p_class int, p_no int) returns jsonb
language sql security definer set search_path = public as $$
  select case when not hn_auth(p_class, p_no, p_pin) then null else jsonb_build_object(
    'card', (select to_jsonb(c) - 'assigned_no' - 'assigned_name' - 'assigned_at' - 'reply_no' - 'reply_name' - 'reply_lines' - 'reply_meds'
             from hn_cards c where class_no = p_class and student_no = p_no),
    'replies', (select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'lines', r.lines, 'meds', r.meds, 'best', r.best) order by r.done_at), '[]'::jsonb)
                from hn_replies r join hn_cards c on c.id = r.card_id
                where c.class_no = p_class and c.student_no = p_no and r.lines is not null),
    'stamps', (select coalesce(jsonb_agg(jsonb_build_object('avatar', c.avatar, 'guest_name', c.guest_name, 'best', r.best) order by r.done_at), '[]'::jsonb)
               from hn_replies r join hn_cards c on c.id = r.card_id
               where r.class_no = p_class and r.reply_no = p_no and r.lines is not null)
  ) end;
$$;

-- 배달: 답장이 적게 달린 문진표부터, 내가 아직 답장 안 한 친구 것만, 문진표당 최대 5개
create or replace function public.hn_get_delivery(p_pin text, p_class int, p_no int, p_name text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare cid uuid; r hn_cards;
begin
  if not hn_auth(p_class, p_no, p_pin) then return null; end if;
  select card_id into cid from hn_replies
   where class_no = p_class and reply_no = p_no and lines is null and started_at > now() - interval '15 minutes' limit 1;
  if cid is null then
    delete from hn_replies where class_no = p_class and lines is null and started_at <= now() - interval '15 minutes';
    select c.id into cid from hn_cards c
     where c.class_no = p_class and c.student_no <> p_no and not c.hidden
       and not exists (select 1 from hn_replies x where x.card_id = c.id and x.reply_no = p_no)
       and (select count(*) from hn_replies x where x.card_id = c.id) < 5
     order by (select count(*) from hn_replies x where x.card_id = c.id), random()
     limit 1;
    if cid is null then return null; end if;
    insert into hn_replies (card_id, class_no, reply_no) values (cid, p_class, p_no) on conflict do nothing;
  end if;
  select * into r from hn_cards where id = cid;
  return jsonb_build_object('id', r.id, 'avatar', r.avatar, 'guest_name', r.guest_name,
    'symptoms', r.symptoms, 'feel', r.feel, 'card_lines', r.card_lines);
end $$;

create or replace function public.hn_submit_reply(
  p_pin text, p_card uuid, p_class int, p_no int, p_name text, p_meds text[], p_advice text, p_lines jsonb
) returns text
language plpgsql security definer set search_path = public as $$
begin
  if not hn_auth(p_class, p_no, p_pin) then return 'pin'; end if;
  if jsonb_array_length(coalesce(p_lines,'[]'::jsonb)) > 6 or length(coalesce(p_lines::text,'')) > 600 then return 'bad'; end if;
  update hn_replies set lines = p_lines, meds = p_meds[1:4], done_at = now()
   where card_id = p_card and class_no = p_class and reply_no = p_no and lines is null;
  if found then return 'ok'; end if;
  return 'fail';
end $$;

-- 손님이 받은 답장 중 제일 마음에 드는 것 고르기 (최대 2개, 준 건 그대로) → 답장 쓴 친구에게 스페셜 도장
create or replace function public.hn_pick_best(p_pin text, p_class int, p_no int, p_reply bigint) returns text
language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if not hn_auth(p_class, p_no, p_pin) then return 'pin'; end if;
  select c.id into cid from hn_cards c join hn_replies r on r.card_id = c.id
   where c.class_no = p_class and c.student_no = p_no and r.id = p_reply and r.lines is not null;
  if cid is null then return 'fail'; end if;
  if exists (select 1 from hn_replies where id = p_reply and best) then return 'ok'; end if;
  -- 한 번 준 💖 는 그대로, 문진표 하나당 최대 2개까지 (처음 고르기 + 한 번 더)
  if (select count(*) from hn_replies where card_id = cid and best) >= 2 then return 'limit'; end if;
  update hn_replies set best = true where id = p_reply;
  return 'ok';
end $$;

-- 우리 반 처방 수 (목표 게이지용)
create or replace function public.hn_class_progress(p_class int) returns int
language sql security definer set search_path = public as $$
  select count(*)::int from hn_replies where class_no = p_class and lines is not null;
$$;

create or replace function public.hn_save_score(p_class int, p_names text, p_score int, p_cured int, p_total int) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if p_class not between 1 and 4 then return false; end if;
  insert into hn_scores (class_no, names, score, cured, total)
  values (p_class, left(coalesce(p_names,'?'),40), least(greatest(p_score,0),99999), least(greatest(p_cured,0),50), least(greatest(p_total,0),50));
  return true;
end $$;

create or replace function public.hn_top_scores(p_class int) returns jsonb
language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(t), '[]'::jsonb) from (
    select names, score, cured, total from hn_scores
    where class_no = p_class and created_at > now() - interval '30 days'
    order by score desc, created_at limit 5) t;
$$;

create or replace function public.hn_featured() returns jsonb
language sql security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object('avatar', avatar, 'guest_name', guest_name,
    'symptoms', symptoms, 'feel', feel, 'card_lines', card_lines, 'class_no', class_no)), '[]'::jsonb)
  from hn_cards where featured and not hidden;
$$;

create or replace function public.hn_teacher_data(p_pw text, p_class int) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return null; end if;
  return jsonb_build_object(
    'cards', (select coalesce(jsonb_agg((to_jsonb(c) - 'reply_no' - 'reply_name' - 'reply_lines' - 'reply_meds') || jsonb_build_object('replies',
        (select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'reply_no', r.reply_no, 'lines', r.lines, 'best', r.best) order by r.done_at), '[]'::jsonb)
         from hn_replies r where r.card_id = c.id and r.lines is not null)) order by c.student_no), '[]'::jsonb)
      from hn_cards c where class_no = p_class),
    'replies_total', (select count(*) from hn_replies where class_no = p_class and lines is not null),
    'scores', '[]'::jsonb,
    'numbers', (select numbers->>(p_class::text) from hn_settings where id = 1),
    'student_pin', (select student_pin from hn_settings where id = 1)
  );
end $$;

create or replace function public.hn_teacher_del_reply(p_pw text, p_reply bigint) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  delete from hn_replies where id = p_reply;
  return true;
end $$;

-- 교사: 반 학생 목록 (비밀번호 등록 여부, 마지막 접속, 문진표, 쓴 답장 수)
create or replace function public.hn_teacher_students(p_pw text, p_class int) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return null; end if;
  return (select coalesce(jsonb_agg(x order by x.no), '[]'::jsonb) from (
    select n.no,
      exists (select 1 from hn_students s where s.class_no = p_class and s.student_no = n.no) as registered,
      (select last_at from hn_students s where s.class_no = p_class and s.student_no = n.no) as last_at,
      exists (select 1 from hn_cards c where c.class_no = p_class and c.student_no = n.no) as has_card,
      (select count(*) from hn_replies r where r.class_no = p_class and r.reply_no = n.no and r.lines is not null) as replies
    from (select student_no as no from hn_students where class_no = p_class
          union select student_no from hn_cards where class_no = p_class
          union select reply_no from hn_replies where class_no = p_class) n) x);
end $$;

-- 교사: 'reset' 비밀번호 초기화(학생이 다시 정함) / 'setpin' 새 비밀번호 / 'delete' 학생 기록 모두 삭제
create or replace function public.hn_teacher_student(p_pw text, p_class int, p_no int, p_action text, p_pin text) returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not hn_pw_ok(p_pw) then return 'pw'; end if;
  if p_action = 'reset' then
    delete from hn_students where class_no = p_class and student_no = p_no;
  elsif p_action = 'setpin' then
    if length(coalesce(p_pin,'')) not between 4 and 12 then return 'bad'; end if;
    insert into hn_students (class_no, student_no, pin_hash) values (p_class, p_no, crypt(p_pin, gen_salt('bf')))
    on conflict (class_no, student_no) do update set pin_hash = excluded.pin_hash;
  elsif p_action = 'delete' then
    delete from hn_replies where class_no = p_class and reply_no = p_no;
    delete from hn_cards where class_no = p_class and student_no = p_no;
    delete from hn_students where class_no = p_class and student_no = p_no;
  else return 'bad'; end if;
  return 'ok';
end $$;

create or replace function public.hn_teacher_action(p_pw text, p_card uuid, p_action text) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  if p_action = 'hide' then update hn_cards set hidden = true where id = p_card;
  elsif p_action = 'unhide' then update hn_cards set hidden = false where id = p_card;
  elsif p_action = 'feature' then update hn_cards set featured = true where id = p_card;
  elsif p_action = 'unfeature' then update hn_cards set featured = false where id = p_card;
  elsif p_action = 'clear_reply' then delete from hn_replies where card_id = p_card;
  elsif p_action = 'delete' then delete from hn_cards where id = p_card;
  else return false; end if;
  return true;
end $$;

create or replace function public.hn_clear_scores(p_pw text, p_class int) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  delete from hn_scores where class_no = p_class;
  return true;
end $$;

grant execute on function public.hn_has_pw(), public.hn_setup_pw(text), public.hn_teacher_login(text),
  public.hn_change_pw(text,text), public.hn_get_numbers(int), public.hn_set_numbers(text,int,text),
  public.hn_submit_card(text,int,int,text,text,text,text[],text,text,jsonb), public.hn_my_card(text,int,int),
  public.hn_get_delivery(text,int,int,text), public.hn_submit_reply(text,uuid,int,int,text,text[],text,jsonb),
  public.hn_check_pin(text), public.hn_set_student_pin(text,text),
  public.hn_student_login(int,int,text), public.hn_student_register(int,int,text),
  public.hn_teacher_students(text,int), public.hn_teacher_student(text,int,int,text,text),
  public.hn_class_progress(int), public.hn_teacher_del_reply(text,bigint), public.hn_pick_best(text,int,int,bigint),
  public.hn_save_score(int,text,int,int,int), public.hn_top_scores(int), public.hn_featured(),
  public.hn_teacher_data(text,int), public.hn_teacher_action(text,uuid,text), public.hn_clear_scores(text,int)
  to anon, authenticated;
-- 글 고치기 (학생 본인) : 손님 이름 + 문진표 문장
create or replace function public.hn_edit_card(p_pin text, p_class int, p_no int, p_guest text, p_lines jsonb) returns text
language plpgsql security definer set search_path = public as $$
begin
  if not hn_auth(p_class, p_no, p_pin) then return 'pin'; end if;
  if jsonb_array_length(coalesce(p_lines,'[]'::jsonb)) not between 1 and 10 or length(p_lines::text) > 1000 then return 'bad'; end if;
  update hn_cards set guest_name = left(coalesce(p_guest, guest_name),20), card_lines = p_lines, updated_at = now()
   where class_no = p_class and student_no = p_no;
  if found then return 'ok'; end if;
  return 'fail';
end $$;

-- 글 고치기 (학생 본인) : 내가 쓴 처방 답장
create or replace function public.hn_edit_reply(p_pin text, p_class int, p_no int, p_reply bigint, p_lines jsonb) returns text
language plpgsql security definer set search_path = public as $$
begin
  if not hn_auth(p_class, p_no, p_pin) then return 'pin'; end if;
  if jsonb_array_length(coalesce(p_lines,'[]'::jsonb)) not between 1 and 6 or length(p_lines::text) > 600 then return 'bad'; end if;
  update hn_replies set lines = p_lines where id = p_reply and class_no = p_class and reply_no = p_no and lines is not null;
  if found then return 'ok'; end if;
  return 'fail';
end $$;

-- 내가 쓴 처방 목록 (고치기용)
create or replace function public.hn_my_replies(p_pin text, p_class int, p_no int) returns jsonb
language sql security definer set search_path = public as $$
  select case when not hn_auth(p_class, p_no, p_pin) then null else
    (select coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'lines', r.lines, 'best', r.best,
       'guest_name', c.guest_name, 'avatar', c.avatar, 'card_lines', c.card_lines) order by r.done_at), '[]'::jsonb)
     from hn_replies r join hn_cards c on c.id = r.card_id
     where r.class_no = p_class and r.reply_no = p_no and r.lines is not null) end;
$$;

-- 교사: 학생 글 고치기
create or replace function public.hn_teacher_edit_card(p_pw text, p_card uuid, p_guest text, p_lines jsonb) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  update hn_cards set guest_name = left(coalesce(nullif(trim(p_guest),''), guest_name),20),
    card_lines = case when jsonb_typeof(p_lines) = 'array' then p_lines else card_lines end, updated_at = now() where id = p_card;
  return found;
end $$;

create or replace function public.hn_teacher_edit_reply(p_pw text, p_reply bigint, p_lines jsonb) returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return false; end if;
  if jsonb_typeof(p_lines) <> 'array' then return false; end if;
  update hn_replies set lines = p_lines where id = p_reply;
  return found;
end $$;

-- 교사: 성적표 문구용 학생별 자료 (문진표 + 쓴 답장 + 받은 💖)
create or replace function public.hn_teacher_report(p_pw text, p_class int) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not hn_pw_ok(p_pw) then return null; end if;
  return (select coalesce(jsonb_agg(x order by x.no), '[]'::jsonb) from (
    select n.no,
      (select jsonb_build_object('guest_name', c.guest_name, 'symptoms', c.symptoms, 'feel', c.feel, 'extra', c.extra, 'lines', c.card_lines)
         from hn_cards c where c.class_no = p_class and c.student_no = n.no) as card,
      (select coalesce(jsonb_agg(jsonb_build_object('lines', r.lines, 'best', r.best) order by r.done_at), '[]'::jsonb)
         from hn_replies r where r.class_no = p_class and r.reply_no = n.no and r.lines is not null) as written,
      (select count(*) from hn_replies r join hn_cards c on c.id = r.card_id
         where c.class_no = p_class and c.student_no = n.no and r.lines is not null) as received
    from (select student_no as no from hn_students where class_no = p_class
          union select student_no from hn_cards where class_no = p_class
          union select reply_no from hn_replies where class_no = p_class) n) x);
end $$;

grant execute on function public.hn_edit_card(text,int,int,text,jsonb), public.hn_edit_reply(text,int,int,bigint,jsonb),
  public.hn_my_replies(text,int,int), public.hn_teacher_edit_card(text,uuid,text,jsonb),
  public.hn_teacher_edit_reply(text,bigint,jsonb), public.hn_teacher_report(text,int) to anon, authenticated;
