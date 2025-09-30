import argparse
import os


def hex_to_gds(hex_string, output_file):
    """
    Конвертирует hex строку обратно в GDS файл
    """
    try:
        # Конвертируем hex строку обратно в бинарные данные
        binary_data = bytes.fromhex(hex_string)

        # Сохраняем как бинарный файл
        with open(output_file, 'wb') as f:
            f.write(binary_data)

        print(f"Hex строка конвертирована в GDS файл: {output_file}")
        return True

    except ValueError as e:
        print(f"Ошибка: Неверный формат hex строки: {e}")
        return False


def base64_to_gds(base64_string, output_file):
    """
    Конвертирует base64 строку обратно в GDS файл
    """
    import base64

    try:
        # Конвертируем base64 обратно в бинарные данные
        binary_data = base64.b64decode(base64_string)

        # Сохраняем как бинарный файл
        with open(output_file, 'wb') as f:
            f.write(binary_data)

        print(f"Base64 строка конвертирована в GDS файл: {output_file}")
        return True

    except Exception as e:
        print(f"Ошибка: Неверный формат base64 строки: {e}")
        return False


def string_to_gds(input_string, output_file, input_format='auto'):
    """
    Универсальная функция для конвертации строки в GDS файл
    """
    # Автоматическое определение формата
    if input_format == 'auto':
        # Проверяем, является ли строка hex (только hex символы)
        if all(c in '0123456789abcdefABCDEF' for c in input_string.strip()):
            input_format = 'hex'
        else:
            input_format = 'base64'

    if input_format == 'hex':
        return hex_to_gds(input_string, output_file)
    else:
        return base64_to_gds(input_string, output_file)


def file_to_gds(input_file, output_file, input_format='auto'):
    """
    Конвертирует файл со строкой обратно в GDS
    """
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Файл {input_file} не найден")

    with open(input_file, 'r') as f:
        string_data = f.read().strip()

    return string_to_gds(string_data, output_file, input_format)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Конвертация строки обратно в GDS файл')
    parser.add_argument('input', help='Входная строка или файл со строкой')
    parser.add_argument('output_file', help='Выходной GDS файл')
    parser.add_argument('-f', '--format', choices=['auto', 'hex', 'base64'], default='auto',
                        help='Формат входных данных')
    parser.add_argument('-i', '--is-file', action='store_true',
                        help='Указать если input это файл со строкой')

    args = parser.parse_args()

    try:
        if args.is_file:
            success = file_to_gds(args.input, args.output_file, args.format)
        else:
            success = string_to_gds(args.input, args.output_file, args.format)

        if success:
            print("Конвертация завершена успешно!")
        else:
            print("Конвертация завершена с ошибками!")

    except Exception as e:
        print(f"Ошибка: {e}")