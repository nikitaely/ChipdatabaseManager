import argparse
import os


def gds_to_hex(input_file, output_file=None):
    """
    Конвертирует GDS файл в hex строку
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Файл {input_file} не найден")

    # Читаем бинарный файл
    with open(input_file, 'rb') as f:
        binary_data = f.read()

    # Конвертируем в hex строку
    hex_string = binary_data.hex()

    # Сохраняем в файл если указан output
    if output_file:
        with open(output_file, 'w') as f:
            f.write(hex_string)
        print(f"GDS файл конвертирован в hex строку: {output_file}")

    return hex_string


def gds_to_base64(input_file, output_file=None):
    """
    Конвертирует GDS файл в base64 строку (альтернативный вариант)
    """
    import base64

    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Файл {input_file} не найден")

    with open(input_file, 'rb') as f:
        binary_data = f.read()

    # Конвертируем в base64
    base64_string = base64.b64encode(binary_data).decode('utf-8')

    if output_file:
        with open(output_file, 'w') as f:
            f.write(base64_string)
        print(f"GDS файл конвертирован в base64 строку: {output_file}")

    return base64_string


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Конвертация GDS файла в строку')
    parser.add_argument('input_file', help='Входной GDS файл')
    parser.add_argument('-o', '--output', help='Выходной файл')
    parser.add_argument('-f', '--format', choices=['hex', 'base64'], default='hex',
                        help='Формат вывода (hex или base64)')

    args = parser.parse_args()

    try:
        if args.format == 'hex':
            result = gds_to_hex(args.input_file, args.output)
        else:
            result = gds_to_base64(args.input_file, args.output)

        if not args.output:
            # Выводим только первые 100 символов для предпросмотра
            preview = result[:100] + "..." if len(result) > 100 else result
            print(f"Результат ({len(result)} символов): {preview}")

    except Exception as e:
        print(f"Ошибка: {e}")