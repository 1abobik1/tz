package portscan

import "fmt"

// Ports неизменяемый набор портов
type Ports struct {
	values []uint16
	err    error
}

// List выбирает отдельные порты; Scan возвращает ошибки проверки
func List(ports ...int) Ports {
	p := Ports{}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return Ports{err: fmt.Errorf("portscan: invalid port %d (want 1..65535)", port)}
		}

		p.values = append(p.values, uint16(port))
	}

	return p
}

// Range выбирает диапазон включительно; Scan проверяет границы
func Range(first, last int) Ports {
	if first < 1 || last > 65535 || first > last {
		return Ports{err: fmt.Errorf("portscan: invalid port range %d..%d", first, last)}
	}

	p := Ports{values: make([]uint16, 0, last-first+1)}

	for port := first; port <= last; port++ {
		p.values = append(p.values, uint16(port))
	}

	return p
}

// Union объединяет наборы портов; Scan удаляет повторы
func Union(selections ...Ports) Ports {
	p := Ports{}

	for _, selection := range selections {
		if selection.err != nil {
			return Ports{err: selection.err}
		}

		p.values = append(p.values, selection.values...)
	}

	return p
}
