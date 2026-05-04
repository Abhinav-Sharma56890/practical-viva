// In-memory data structures
const users = [];
const products = [
    { id: 1, name: 'Laptop', price: 1200, stock: 10, category: 'Electronics' },
    { id: 2, name: 'Mouse', price: 25, stock: 50, category: 'Accessories' }
];
const orders = [];
const refreshTokens = new Set();

/**
 * Logic Challenge: Compute total price dynamically
 * This looks up the current product prices from the "DB" to ensure price integrity
 */
function calculateTotal(orderId) {
    const order = orders.find(o => o.id === orderId);
    if (!order) return 0;

    return order.items.reduce((total, item) => {
        const product = products.find(p => p.id === item.productId);
        return total + (product ? product.price * item.quantity : 0);
    }, 0);
}

module.exports = { 
    users, 
    products, 
    orders, 
    refreshTokens, 
    calculateTotal 
};