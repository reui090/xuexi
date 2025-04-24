import hashlib
import multiprocessing as mp
import logging
import coincurve
import secrets
import argparse
import time
import os

# 默认参数
DEFAULT_CHUNK_SIZE = 50000
BATCH_SIZE = 1000
STATS_INTERVAL = 10  # 每几秒打印一次性能统计

# 设置日志
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# 保存结果的文件
RESULT_FILE = "found_keys.txt"

def generate_random_keys_in_range(start: int, end: int, count: int) -> list:
    """生成指定范围内的多个随机私钥"""
    return [secrets.randbelow(end - start + 1) + start for _ in range(count)]

def process_private_keys(private_keys_int, target_hash160):
    for priv_int in private_keys_int:
        private_key = priv_int.to_bytes(32, 'big')
        try:
            pubkey = coincurve.PublicKey.from_secret(private_key).format(compressed=True)
            hash160 = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
            if hash160 == target_hash160:
                result = (
                    f"Found!\n"
                    f"Private Key: {private_key.hex()}\n"
                    f"Public Key: {pubkey.hex()}\n"
                    f"HASH160: {hash160.hex()}\n"
                )
                logging.warning(result)
                with open(RESULT_FILE, "a") as f:
                    f.write(result + "\n")
                return result
        except Exception as e:
            continue
    return None

def worker(args):
    chunk_size, range_start, range_end, target_hash160 = args
    batches = chunk_size // BATCH_SIZE
    for _ in range(batches):
        keys = generate_random_keys_in_range(range_start, range_end, BATCH_SIZE)
        result = process_private_keys(keys, target_hash160)
        if result:
            return result
    return None

def parse_args():
    parser = argparse.ArgumentParser(description="CPU Bitcoin Key Searcher (optimized)")
    parser.add_argument('--range-start', type=lambda x: int(x, 16), required=True, help="起始私钥（十六进制）")
    parser.add_argument('--range-end', type=lambda x: int(x, 16), required=True, help="结束私钥（十六进制）")
    parser.add_argument('--target-hash160', type=str, required=True, help="目标 HASH160")
    parser.add_argument('--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE, help="每个任务处理多少密钥")
    parser.add_argument('--threads', type=int, default=mp.cpu_count(), help="使用的进程数")
    return parser.parse_args()

def main():
    args = parse_args()
    target_hash160 = bytes.fromhex(args.target_hash160)

    logging.info(f"使用 {args.threads} 个进程搜索私钥...")
    logging.info(f"范围：{hex(args.range_start)} ~ {hex(args.range_end)}")
    logging.info(f"HASH160 目标值：{args.target_hash160}")

    total_keys_checked = 0
    last_stat_time = time.time()

    with mp.Pool(processes=args.threads) as pool:
        tasks = [(args.chunk_size, args.range_start, args.range_end, target_hash160)] * 99999999  # 无限任务

        for result in pool.imap_unordered(worker, tasks):
            total_keys_checked += args.chunk_size
            now = time.time()

            if now - last_stat_time >= STATS_INTERVAL:
                keys_per_sec = total_keys_checked / (now - last_stat_time)
                logging.info(f"[STATS] 已处理：{total_keys_checked:,} keys | 当前速率：{int(keys_per_sec):,} keys/s")
                total_keys_checked = 0
                last_stat_time = now

            if result:  # 找到了目标，退出
                logging.warning("目标已找到，程序终止。")
                pool.terminate()
                break

if __name__ == "__main__":
    main()
