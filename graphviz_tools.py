import graphviz


def generate_dot_for_llil_var(root: str, tree: dict):
    dot = graphviz.Digraph(f'{root}', comment='The Round Table')
    index = 0

    def _fill_content(parent=None, _tree=None):
        nonlocal index
        if parent is None:
            if tree.get("left_child") is not None:
                left = _fill_content("root", tree["left_child"])
                dot.edge(root, left)
            if tree.get("right_child") is not None:
                right = _fill_content("root", tree["right_child"])
                dot.edge(root, right)
            if tree.get("child"):
                child = _fill_content("root", tree["child"])
                dot.edge(root, child)
        else:
            llil = _tree["il"]
            current_node_text = f"{index}\n{hex(llil.address)}\n{llil.operation.name}\n{str(llil)}"
            index += 1
            if _tree.get("left_child") is not None:
                left = _fill_content(current_node_text, _tree["left_child"])
                dot.edge(current_node_text, left)
            if _tree.get("right_child") is not None:
                right = _fill_content(current_node_text, _tree["right_child"])
                dot.edge(current_node_text, right)

            if _tree.get("child"):
                child = _fill_content(current_node_text, _tree["child"])
                dot.edge(current_node_text, child)

            return current_node_text

    _fill_content()

    dot.render(directory='doctest-output', view=True)


if __name__ == '__main__':
    dot = graphviz.Digraph('hello')
