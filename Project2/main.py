import cv2
import numpy as np
import pywt

def embed_watermark(cover_image_path, watermark_path, output_path, alpha=0.05):
    """
    向载体图像中嵌入水印
    
    参数:
        cover_image_path: 载体图像路径
        watermark_path: 水印图像路径
        output_path: 嵌入水印后的图像保存路径
        alpha: 水印嵌入强度
    """
    # 读取载体图像并转换为灰度图
    cover_image = cv2.imread(cover_image_path, cv2.IMREAD_GRAYSCALE).astype(np.float32)
    # 读取水印图像并转换为灰度图
    watermark = cv2.imread(watermark_path, cv2.IMREAD_GRAYSCALE).astype(np.float32)
    
    # 调整水印尺寸以匹配载体图像的高频分量尺寸
    watermark_resized = cv2.resize(watermark, 
                                  (cover_image.shape[1] // 2, 
                                   cover_image.shape[0] // 2))
    
    # 对载体图像进行二维小波变换
    coeffs = pywt.dwt2(cover_image, 'haar')
    ll, (lh, hl, hh) = coeffs
    
    # 在LH高频分量中嵌入水印
    lh_with_watermark = lh + alpha * watermark_resized
    
    # 重构带有水印的小波系数
    coeffs_with_watermark = (ll, (lh_with_watermark, hl, hh))
    
    # 小波逆变换得到含水印图像
    watermarked_image = pywt.idwt2(coeffs_with_watermark, 'haar')
    
    # 处理像素值范围并保存图像
    cv2.imwrite(output_path, np.uint8(np.clip(watermarked_image, 0, 255)))


def extract_watermark(watermarked_image_path, original_image_path, 
                     watermark_shape, alpha=0.05):
    """
    从含水印图像中提取水印
    
    参数:
        watermarked_image_path: 含水印图像路径
        original_image_path: 原始载体图像路径
        watermark_shape: 原始水印图像的尺寸 (高, 宽)
        alpha: 水印嵌入强度（需与嵌入时保持一致）
    
    返回:
        提取出的水印图像
    """
    # 读取含水印图像和原始载体图像
    watermarked_image = cv2.imread(watermarked_image_path, 
                                  cv2.IMREAD_GRAYSCALE).astype(np.float32)
    original_image = cv2.imread(original_image_path, 
                               cv2.IMREAD_GRAYSCALE).astype(np.float32)
    
    # 对含水印图像进行小波变换
    coeffs_watermarked = pywt.dwt2(watermarked_image, 'haar')
    ll_wm, (lh_wm, hl_wm, hh_wm) = coeffs_watermarked
    
    # 对原始载体图像进行小波变换
    coeffs_original = pywt.dwt2(original_image, 'haar')
    ll_orig, (lh_orig, hl_orig, hh_orig) = coeffs_original
    
    # 提取水印
    extracted_watermark = (lh_wm - lh_orig) / alpha
    
    # 调整水印尺寸至原始大小
    extracted_watermark = cv2.resize(extracted_watermark, 
                                   (watermark_shape[1], watermark_shape[0]))
    
    # 处理像素值范围并返回
    return np.uint8(np.clip(extracted_watermark, 0, 255))


def apply_flip_attack(image_path):
    """对图像应用水平翻转攻击"""
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    flipped_image = cv2.flip(image, 1)  # 1表示水平翻转
    output_path = 'flipped_output.png'
    cv2.imwrite(output_path, flipped_image)
    return output_path


def apply_shift_attack(image_path):
    """对图像应用平移攻击"""
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    rows, cols = image.shape[:2]
    
    # 定义平移矩阵：x方向平移30像素，y方向平移50像素
    translation_matrix = np.float32([[1, 0, 30],
                                    [0, 1, 50]])
    
    shifted_image = cv2.warpAffine(image, translation_matrix, (cols, rows))
    output_path = 'shifted_output.png'
    cv2.imwrite(output_path, shifted_image)
    return output_path


def apply_crop_attack(image_path):
    """对图像应用裁剪攻击"""
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    rows, cols = image.shape[:2]
    
    # 裁剪区域并缩放回原始尺寸
    cropped_image = image[50:200, 100:300]
    cropped_image = cv2.resize(cropped_image, (cols, rows))
    
    output_path = 'cropped_output.png'
    cv2.imwrite(output_path, cropped_image)
    return output_path


def apply_contrast_attack(image_path):
    """对图像应用对比度调整攻击"""
    image = cv2.imread(image_path, cv2.IMREAD_COLOR)
    
    # 调整对比度（alpha=1.5表示增强50%的对比度）
    alpha = 1.5
    beta = 0  # 亮度不变
    contrasted_image = cv2.convertScaleAbs(image, alpha=alpha, beta=beta)
    
    output_path = 'contrast_output.png'
    cv2.imwrite(output_path, contrasted_image)
    return output_path


if __name__ == "__main__":
    # 水印嵌入参数
    embedding_strength = 0.25
    watermark_size = (120, 418)  # 水印图像尺寸 (高, 宽)
    
    # 嵌入水印
    embed_watermark('reference.png', 'watermark.png', 
                   'output.png', embedding_strength)
    
    # 从原始含水印图像中提取水印
    extracted_watermark = extract_watermark('output.png', 'reference.png', 
                                           watermark_size, embedding_strength)
    cv2.imwrite("results/extracted.png", extracted_watermark)
    
    # 应用各种攻击并提取水印
    attack_functions = [
        apply_flip_attack,
        apply_shift_attack,
        apply_crop_attack,
        apply_contrast_attack
    ]
    
    for attack_func in attack_functions:
        # 应用攻击
        attacked_path = attack_func('output.png')
        
        # 从受攻击的图像中提取水印
        attacked_extracted = extract_watermark(attacked_path, 'reference.png', 
                                             watermark_size, embedding_strength)
        
        # 保存提取结果
        result_path = f"results/{attacked_path.split('_')[0]}_extracted.png"
        cv2.imwrite(result_path, attacked_extracted)
