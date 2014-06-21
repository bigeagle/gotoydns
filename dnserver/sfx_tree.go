package toydns

type suffixTreeNode struct {
	key      string
	value    interface{}
	children map[string]*suffixTreeNode
}

func newSuffixTree(key string, value interface{}) *suffixTreeNode {
	root := &suffixTreeNode{
		key:      key,
		value:    value,
		children: map[string]*suffixTreeNode{},
	}
	return root
}

func (node *suffixTreeNode) ensureSubTree(key string) {
	if _, ok := node.children[key]; !ok {
		node.children[key] = newSuffixTree(key, nil)
	}
}

func (node *suffixTreeNode) insert(key string, value interface{}) {
	if c, ok := node.children[key]; ok {
		c.value = value
	} else {
		node.children[key] = newSuffixTree(key, value)
	}
}

func (node *suffixTreeNode) sinsert(keys []string, value interface{}) {
	if len(keys) == 0 {
		return
	}

	key := keys[len(keys)-1]
	if len(keys) > 1 {
		node.ensureSubTree(key)
		node.children[key].sinsert(keys[:len(keys)-1], value)
		return
	}

	node.insert(key, value)
}

func (node *suffixTreeNode) search(keys []string) (interface{}, bool) {
	if len(keys) == 0 {
		return nil, false
	}

	key := keys[len(keys)-1]
	if n, ok := node.children[key]; ok {
		if nextValue, found := n.search(keys[:len(keys)-1]); found {
			return nextValue, found
		}
		return n.value, (n.value != nil)
	}

	return nil, false
}
