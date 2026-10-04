from ids.ml_detector import train_and_evaluate

if __name__ == '__main__':
    metrics = train_and_evaluate()
    print('Random Forest evaluation:')
    for key, value in metrics.items():
        print(f'{key}: {value}')
