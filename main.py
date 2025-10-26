import argparse
import sys
from commands import (
    library_info,
    list_slots,
    list_wallets,
    list_objects,
    generate_key_pair,
    delete_key_pair,
)

# Для Windows: переключаем потоки в UTF-8, чтобы не падать на кириллице
if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


class CustomArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        base_help = super().format_help()
        return "Инструмент для работы с wtpkcs11ecp\n" + base_help


def main():
    parser = CustomArgumentParser(
        description='Утилита для работы с PKCS#11 библиотекой Рутокен',
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
    )
    parser.add_argument(
        '-h',
        '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='Показать это справочное сообщение и завершить работу',
    )
    parser.add_argument('--library-info', action='store_true',
                        help='Показать информацию о библиотеке (C_GetInfo)')
    parser.add_argument('--list-slots', action='store_true',
                        help='Показать список доступных слотов')
    parser.add_argument('--list-wallets', action='store_true',
                        help='Показать список кошельков (токенов)')
    parser.add_argument('--list-objects', action='store_true',
                        help='Показать список объектов в кошельке')
    parser.add_argument('--generate-key', choices=['secp256', 'ed25519', 'gost', 'rsa1024', 'rsa2048'],
                        help='Сгенерировать ключевую пару указанного типа')
    parser.add_argument('--key-id', type=str, default='',
                        help='CKA_ID для создаваемой ключевой пары')
    parser.add_argument('--key-label', type=str, default='',
                        help='CKA_LABEL для создаваемой ключевой пары')
    parser.add_argument('--delete-key', type=int,
                        help='Удалить ключевую пару по номеру')
    parser.add_argument('--slot-id', type=int, default=0,
                        help='Идентификатор слота для выполнения команды (по умолчанию 0)')
    parser.add_argument('--pin', type=str, default=None,
                        help='PIN-код для выполнения команды (если требуется)')

    args = parser.parse_args()

    if args.library_info:
        library_info()
    elif args.list_slots:
        list_slots()
    elif args.list_wallets:
        list_wallets()
    elif args.list_objects:
        list_objects(args.slot_id, args.pin)
    elif args.generate_key:
        if not args.key_id or not args.key_label:
            print('Необходимо указать --key-id и --key-label для генерации ключа', file=sys.stderr)
        else:
            generate_key_pair(
                args.slot_id,
                args.pin,
                args.generate_key,
                cka_id=args.key_id,
                cka_label=args.key_label,
            )
    elif args.delete_key is not None:
        delete_key_pair(args.slot_id, args.pin, args.delete_key)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
