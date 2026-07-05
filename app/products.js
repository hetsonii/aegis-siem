'use strict';
// In-memory catalog. There is deliberately no database: user input never
// reaches a query, so injection payloads have nothing to inject into.
module.exports = [
  { id: 1, name: 'Sunrise Orange', emoji: '🍊', price: 4.50, tag: 'citrus', desc: 'Cold-pressed Valencia oranges with a hint of ginger.' },
  { id: 2, name: 'Green Detox', emoji: '🥬', price: 5.25, tag: 'green', desc: 'Kale, cucumber, celery, green apple, and lemon.' },
  { id: 3, name: 'Berry Blast', emoji: '🫐', price: 4.75, tag: 'berry', desc: 'Blueberry, strawberry, and raspberry blend.' },
  { id: 4, name: 'Tropical Mango', emoji: '🥭', price: 5.00, tag: 'tropical', desc: 'Alphonso mango and passion fruit.' },
  { id: 5, name: 'Carrot Ginger', emoji: '🥕', price: 4.25, tag: 'root', desc: 'Carrot, orange, and a fiery ginger kick.' },
  { id: 6, name: 'Watermelon Cooler', emoji: '🍉', price: 3.95, tag: 'melon', desc: 'Pure watermelon with mint. Summer in a bottle.' },
  { id: 7, name: 'Beet Reboot', emoji: '🍠', price: 5.50, tag: 'root', desc: 'Beetroot, apple, and lime. Earthy and bright.' },
  { id: 8, name: 'Pineapple Punch', emoji: '🍍', price: 4.90, tag: 'tropical', desc: 'Pineapple, coconut water, and turmeric.' },
  { id: 9, name: 'Lemon Zinger', emoji: '🍋', price: 3.75, tag: 'citrus', desc: 'Lemon, honey, and cayenne. Wakes you right up.' },
  { id: 10, name: 'Grape Escape', emoji: '🍇', price: 4.60, tag: 'berry', desc: 'Concord grape and black currant.' },
  { id: 11, name: 'Apple Ginger Fizz', emoji: '🍏', price: 4.40, tag: 'green', desc: 'Sparkling green apple with fresh ginger.' },
  { id: 12, name: 'Peach Sunset', emoji: '🍑', price: 4.85, tag: 'tropical', desc: 'White peach, apricot, and a touch of vanilla.' },
];
