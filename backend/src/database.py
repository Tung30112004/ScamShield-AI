from supabase import create_client, Client

from env_config import get_supabase_config, supabase_key_kind

# --- 1. LOAD CẤU HÌNH BIẾN MÔI TRƯỜNG ---
# SUPABASE_URL / SUPABASE_KEY (tên cũ EXPO_PUBLIC_SUPABASE_* vẫn được đọc), xem env_config.py
SUPABASE_URL, SUPABASE_KEY = get_supabase_config()

# supabase-py 2.34 (postgrest 2.x) mặc định chờ 120s/truy vấn và tự retry 3 lần
# (nghỉ 1+2+4s) khi lỗi mạng hoặc 503/520 -> /predict treo 7-15s, thậm chí vài phút,
# khi Supabase lỗi. Giữ hành vi fail-soft như bản 2.3.0: tối đa 5s, không retry.
# Backend không đăng nhập người dùng nên tắt luôn refresh/persist session.
# (Import/tạo trong khối try bên dưới: supabase-py cũ (2.3.0) không có ClientOptions ở
#  cấp gói / không có tham số retry -> chỉ tắt tầng DB, backend vẫn khởi động.)
DB_CLIENT_OPTIONS = dict(
    postgrest_client_timeout=5,
    postgrest_client_retry=False,
    auto_refresh_token=False,
    persist_session=False,
)

# --- 2. KHỞI TẠO KẾT NỐI ---
try:
    if not SUPABASE_URL or not SUPABASE_KEY:
        missing = [n for n, v in (("SUPABASE_URL", SUPABASE_URL), ("SUPABASE_KEY", SUPABASE_KEY)) if not v]
        print(f"⚠️ CẢNH BÁO: Chưa cấu hình {', '.join(missing)} — bỏ qua tra cứu Database Supabase")
        supabase: Client = None
    else:
        from supabase import ClientOptions

        key_kind = supabase_key_kind(SUPABASE_KEY)
        if key_kind in ("secret", "service_role"):
            print(f"⚠️ CẢNH BÁO: SUPABASE_KEY là key quyền cao ({key_kind}) — backend chỉ cần quyền đọc, "
                  "nên dùng key sb_publishable_…")
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY,
                                         options=ClientOptions(**DB_CLIENT_OPTIONS))
        print(f"✅ Kết nối Database Supabase thành công! (key: {key_kind})")
except Exception as e:
    print(f"❌ Lỗi kết nối Database: {e}")
    supabase = None

# --- 3. CÁC HÀM TRA CỨU DANH SÁCH ---

def check_url_in_db(url: str):
    """
    Kiểm tra URL có nằm trong danh sách Phishing hoặc Safe đã có sẵn không.
    Trả về dữ liệu nếu tìm thấy, ngược lại trả về None.
    """
    if not supabase:
        return None
        
    try:
        clean_url = url.strip().lower()
        
        # 1. Tra cứu trong bảng Phishing (Blacklist)
        res_phishing = supabase.table("phishing_urls").select("*").eq("url", clean_url).execute()
        if res_phishing.data and len(res_phishing.data) > 0:
            result = res_phishing.data[0]
            return {**result, "source": "database_blacklist"}
            
        # 2. Tra cứu trong bảng Safe (Whitelist)
        res_safe = supabase.table("safe_urls").select("*").eq("url", clean_url).execute()
        if res_safe.data and len(res_safe.data) > 0:
            result = res_safe.data[0]
            return {**result, "source": "database_whitelist"}
            
        return None
    except Exception as e:
        print(f"⚠️ Lỗi khi tra cứu Database: {e}")
        return None
