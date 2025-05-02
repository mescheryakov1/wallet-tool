import argparse
from commands import library_info, factory_reset, list_slots, list_wallets

def main():
    parser = argparse.ArgumentParser(
        description='Утилита для работы с PKCS#11 библиотекой Рутокен',
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--library-info', action='store_true',
                        help='Показать информацию о библиотеке (C_GetInfo)')
    parser.add_argument('--list-slots', action='store_true',
                        help='Показать список доступных слотов (заглушка)')
    parser.add_argument('--list-wallets', action='store_true',
                        help='Показать список кошельков (заглушка)')
    parser.add_argument('--factory-reset', action='store_true',
                        help='Выполнить фабричный сброс токена (C_EX_InitToken)')
    parser.add_argument('--slot-id', type=int, default=0,
                        help='Идентификатор слота для фабричного сброса (по умолчанию 0)')
    parser.add_argument('--pin', type=str, default='12345678',
                        help='PIN-код для фабричного сброса (по умолчанию "12345678")')
    parser.add_argument('--label', type=str, default='NewToken',
                        help='Метка токена для фабричного сброса (по умолчанию "NewToken")')

    args = parser.parse_args()

    if args.library_info:
        library_info()
    elif args.list_slots:
        list_slots()
    elif args.list_wallets:
        list_wallets()
    elif args.factory_reset:
        factory_reset(args.slot_id, args.pin, args.label)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()