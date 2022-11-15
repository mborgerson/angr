#!/usr/bin/env python3


# FIXME: Use a better memory data item sort. Unknown,Unspecified,Integer will cause 'guess' and change size to None

# FIXME: In the future, we can optimize unflow and reflow methods starting from changed
#        node(s) and removing all reachable nodes. For now, just re-flow the entire function.

# We will lose callers! We need to only trim the outgoing edges
# and leave the function. For now, just leave it.
# proj.kb.functions.callgraph.remove_node(node.addr)

# We don't actually need to do this if we are not recycling the
# functions in make_functions (which we are not today)
# func._clear_transition_graph()

# FIXME: fakerets?
# FIXME: xrefs?
# FIXME: function transitions?

# XXX: The number of functions may be different! With force-scanning enabled,
#      a function will be created at the end of the memory data item (which is
#      considered code still)
#
#      When running again in the future, we would want that function to disappear...
#      make_functions currently (probably) takes care of that for us?

# FIXME: Maybe we should use a different arg than function_starts? We
# could be classifying part of a function as code, in which case it is
# not a function start, rather just code. But we don't have a concept
# of code without being in a function today (afaik)

# FIXME: Once a reference is detected as data (as we do in _start), we
# will fail to correctly identify it as code! We should be able to
# handle a reference as both code and data

# FIXME: Test classifying part of a function's code as data so a function is actually extended
#        - Example case: Failed jump table analysis


import os
import unittest
import logging
import tempfile
from typing import Sequence, Tuple, Optional

import angr
from angr.knowledge_plugins.patches import Patch
from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort


log = logging.getLogger(__name__)
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             "..", "..", "binaries", "tests")


class TestCfgModel(unittest.TestCase):
    """
    Test cases for CFGModel
    """

    def test_cfgmodel_remove_function_nodes(self):
        """
        Test CFGModel::remove_function_nodes
        """
        binary_path = os.path.join(test_location, 'x86_64', 'fauxware')
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        func = cfg.functions['authenticate']
        cfg.model.remove_function_nodes(func)
        for addr in func.block_addrs:
            assert cfg.model.get_any_node(addr) is None


class TestCfgReclassify(unittest.TestCase):
    """
    Tests that code/data can be reclassified in CFG.
    """

    # Tasks:
    # - Support re-classifying code as data
    #   - With re-flow:
    #     - Need to support removing the code from the CFG
    #       - Scoop out node and all following unreachable nodes
    #     - Need to update edge from prior node
    #     - Support removing functions if we are re-classifying them?
    # - Support re-classifying data as code
    #   - Begin CFG from specified location, follow flow. We may discover
    #     functions along the way.
    # - Support function re-flow
    #   - Begin re-flow from a particular node in the function
    #   - Run CFG again with existing model
    # - Support patching
    #   - Analyze patch
    #     - If patch changes control flow, re-flow the function
    #     - If patch does not change control flow, simply update the node

    # Questions:
    # - Q: How can we support updates to functions?
    #   A: Full function re-flow (re-running make_functions)

    @staticmethod
    def _assert_models_equal(model_1: 'CFGModel', model_2: 'CFGModel'):
        assert model_1.nodes() == model_2.nodes()
        # FIXME: Check more stuff (eg edges)

    def _assert_all_function_equal(self, functions_1: 'FunctionManager', functions_2: 'FunctionManager'):
        for f in functions_2:
            assert f in functions_1, f'Extra function: {functions_2[f]}'
        for f in functions_1:
            assert f in functions_2, f'Missing function: {functions_1[f]}'
            self._assert_function_graphs_equal(functions_1[f], functions_2[f])
            # FIXME: Check more stuff (eg edges)

    @staticmethod
    def _assert_function_graphs_equal(function_1: 'Function', function_2: 'Function'):
        nodes_1 = [n for n in function_1.graph.nodes()]
        nodes_2 = [n for n in function_2.graph.nodes()]
        if nodes_1 != nodes_2:
            log.error('Differing nodes!\nFunction:%s\nNodes 1: %s\nNodes 2: %s', function_1, nodes_1, nodes_2)
            assert False

    def test_cfgfast_combine_with_full_model(self):
        """Run CFGFast once, then again with the model of the first"""
        binary_path = os.path.join(test_location, 'x86_64', 'fauxware')
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg_1 = proj.analyses.CFGFast()
        functions_1 = cfg_1.functions.copy()

        cfg_2 = proj.analyses.CFGFast(model=cfg_1.model.copy())
        functions_2 = cfg_2.functions.copy()

        self._assert_models_equal(cfg_1.model, cfg_2.model)
        self._assert_all_function_equal(functions_1, cfg_2.functions)

    def test_cfgfast_combine_with_partial_model(self):
        """Run CFGFast on a region, then again on a second region with the model of the first"""
        binary_path = os.path.join(test_location, 'x86_64', 'fauxware')

        # Initial analysis just to pick up expected addresses
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        accepted_addr = cfg.functions['accepted'].addr
        rejected_addr = cfg.functions['rejected'].addr
        accepted_regions = [(n.addr, n.addr + n.size) for n in cfg.functions['accepted'].nodes]
        rejected_regions = [(n.addr, n.addr + n.size) for n in cfg.functions['rejected'].nodes]

        # Run partial analysis on the nodes we care about
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(regions=accepted_regions)
        assert accepted_addr in cfg.functions.function_addrs_set
        assert rejected_addr not in cfg.functions.function_addrs_set

        # Check continued analysis over another region combines correctly
        cfg = proj.analyses.CFGFast(regions=rejected_regions, model=cfg.model.copy())
        assert accepted_addr in cfg.functions.function_addrs_set
        assert rejected_addr in cfg.functions.function_addrs_set

        # Check analysis over union of regions yields same result
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg_combined = proj.analyses.CFGFast(regions=(accepted_regions + rejected_regions))
        self._assert_models_equal(cfg.model, cfg_combined.model)
        self._assert_all_function_equal(cfg.functions, cfg_combined.functions)

    def test_cfgfast_classify_code_as_data(self):
        """
        Create an empty model, classify some code as data, then run CFGFast and ensure it remains data
        """
        binary_path = os.path.join(test_location, 'x86_64', 'fauxware')
        proj = angr.Project(binary_path, auto_load_libs=False)

        model = proj.kb.cfgs.new_model('initial')
        md = MemoryData(0x40069d, 22, MemoryDataSort.String)
        model.memory_data[md.addr] = md.copy()

        cfg = proj.analyses.CFGFast(model=model)

        assert cfg.model.memory_data[md.addr] == md

        # Make sure the memory data item is not covered by any node
        assert len(cfg.functions['authenticate'].graph.nodes) == 5
        for n in cfg.functions['authenticate'].graph.nodes:
            assert md.addr >= (n.addr + n.size) or n.addr >= (md.addr + md.size)
            if (n.addr + n.size) == md.addr:
                log.debug('Found adjacent node %s', n)
                # FIXME: Successor address is still the same

        # FIXME: Also test at function boundary

    def test_cfgfast_reclassify_code_as_data(self):
        """
        Run CFGFast, re-classify code within a function as data, then re-flow the function.
        """
        binary_path = os.path.join(test_location, 'x86_64', 'fauxware')
        proj = angr.Project(binary_path, auto_load_libs=False)

        # Initial analysis
        cfg = proj.analyses.CFGFast()
        func = cfg.functions['authenticate']
        function_addr = func.addr
        original_number_of_nodes = len(func.graph.nodes)

        # Define the data region and run analysis for function reconstruction
        md = MemoryData(0x40069d, 22, MemoryDataSort.String)
        cfg.model.memory_data[md.addr] = md.copy()
        cfg.model.remove_function_nodes(func)
        cfg = proj.analyses.CFGFast(symbols=False,
                                    function_prologues=False,
                                    start_at_entry=False,
                                    force_smart_scan=False,
                                    force_complete_scan=False,
                                    function_starts=[function_addr],
                                    model=cfg.model)

        # Check memory data remains as configured and is not overlapped by any node
        assert cfg.model.memory_data[md.addr] == md
        assert len(cfg.functions['authenticate'].graph.nodes) == 5
        for n in cfg.functions['authenticate'].graph.nodes:
            assert md.addr >= (n.addr + n.size) or n.addr >= (md.addr + md.size)

        # Now re-define the data as code again and ensure we have the correct number of nodes
        del cfg.model.memory_data[md.addr]
        cfg.model.remove_function_nodes(func)
        cfg = proj.analyses.CFGFast(symbols=False,
                                    function_prologues=False,
                                    start_at_entry=False,
                                    force_smart_scan=False,
                                    force_complete_scan=False,
                                    function_starts=[function_addr],
                                    model=cfg.model)

        assert len(cfg.functions['authenticate'].graph.nodes) == original_number_of_nodes

        # FIXME: Test at function boundary

    # FIXME: Test at partial offset into some data item
    def test_cfgfast_classify_data_as_code(self):
        """
        Classify some code that we would not determine to be code, as code.
        """
        code = '''
        _start:
            ret

        not_discovered:
            xor rax, rax
            mov rcx, 5
            .here:
            inc rax
            dec rcx
            jnz .here
            ret
        '''

        not_discovered_addr = 0x1
        proj = angr.load_shellcode(code, 'AMD64')
        cfg = proj.analyses.CFGFast(force_smart_scan=False)
        assert len(cfg.functions) == 1

        proj = angr.load_shellcode(code, 'AMD64')
        cfg = proj.analyses.CFGFast(force_smart_scan=False,
                                    function_starts=[not_discovered_addr])
        assert len(cfg.functions) == 2
        assert len(cfg.functions[not_discovered_addr].block_addrs) == 3

    def test_cfgfast_reclassify_data_as_code(self):
        """
        Run CFGFast, then re-classify some assumed data as code and run again.
        """
        code = '''
        _start:
            mov rax, [not_discovered]
            ret

        not_discovered:
            xor rax, rax
            mov rcx, 5
            .here:
            inc rax
            dec rcx
            jnz .here
            ret
        '''

        proj = angr.load_shellcode(code, 'AMD64')
        cfg = proj.analyses.CFGFast(force_smart_scan=False)
        assert len(cfg.functions) == 1
        not_discovered_addr = 0xb
        del cfg.model.memory_data[not_discovered_addr]
        cfg = proj.analyses.CFGFast(start_at_entry=False,
                                    force_smart_scan=False,
                                    function_starts=[not_discovered_addr],
                                    model=cfg.model)
        assert len(cfg.functions) == 2
        assert len(cfg.functions[0xb].block_addrs) == 3


class TestCfgPatching(unittest.TestCase):
    """
    Tests that patches made to the binary are correctly processed by CFG.
    """

    @staticmethod
    def _apply_patches(proj, patches):
        for addr, asm in patches:
            patch_bytes = proj.arch.keystone.asm(asm, addr, as_bytes=True)[0]
            proj.kb.patches.add_patch_obj(Patch(addr, patch_bytes))

    @staticmethod
    def _assert_cfgs_equal(expected, result):
        # Check nodes same
        nodes_expected = {n.addr: n.size for n in expected.model.nodes()}
        nodes_result = {n.addr: n.size for n in result.model.nodes()}

        for n in nodes_expected:
            if n not in nodes_result:
                log.error('Test result graph does not have expected node %#x, %#x bytes', n, nodes_expected[n])
                import ipdb; ipdb.set_trace()
                assert False
        for n in nodes_result:
            if n not in nodes_expected:
                log.error('Test result graph has unexpected node %#x, %#x bytes', n, nodes_result[n])
                assert False
            else:
                if nodes_result[n] != nodes_expected[n]:
                    import ipdb; ipdb.set_trace()
                    log.error('Test result graph node at %#x has size %#x bytes, expected %#x bytes', n, nodes_result[n], nodes_expected[n])
                    assert False

        # assert nodes_expected == nodes_result

        # FIXME: Check edges
        # FIXME: Check xrefs
        # FIXME: Check functions

    def _test_patch(self, patches: Sequence[Tuple[int, str]]):
        unpatched_binary_path = os.path.join(test_location, 'x86_64', 'fauxware')
        common_cfg_options = dict(normalize=True, resolve_indirect_jumps=True, data_references=True)

        # Create and load a pre-patched binary
        log.debug('Recovering pre-patched CFG')
        proj = angr.Project(unpatched_binary_path, auto_load_libs=False)
        self._apply_patches(proj, patches)

        with tempfile.NamedTemporaryFile(prefix='fauxware-patched-', delete=False) as f:
            f.write(proj.kb.patches.apply_patches_to_binary())
            f.close()

            prepatched_proj = angr.Project(f.name, auto_load_libs=False)
            expected_cfg = prepatched_proj.analyses.CFGFast(**common_cfg_options)

            # Create unpatched CFG
            # log.debug('Recovering unpatched CFG')
            # unpatched_proj = angr.Project(unpatched_binary_path, auto_load_libs=False)
            # unpatched_cfg = prepatched_proj.analyses.CFGFast(**common_cfg_options)

            # Now create a new project, recover CFG, then patch and recover CFG again
            proj = angr.Project(unpatched_binary_path, auto_load_libs=False)

            log.debug('Recovering CFG before patching')
            cfg_before_patching = proj.analyses.CFGFast(**common_cfg_options)

            self._apply_patches(proj, patches)

            # FIXME: Use function starts and handle recovery of entire binary again
            log.debug('Recovering CFG after patching')
            proj.kb.functions.clear()  # XXX
            cfg_after_patching = proj.analyses.CFGFast(**common_cfg_options,
                                                       model=cfg_before_patching.model,
                                                       use_patches=True)

            # Verify that the CFG of the patched binary matches the CFG of the pre-patched binary
            self._assert_cfgs_equal(expected_cfg, cfg_after_patching)

    #
    # Patches that do not change block or function size
    #

    def test_cfg_patch_const_operand(self):
        """
        Patch a block, just changing some data reference, no affect on control: change print of "Username: " to "Password: "
        """
        self._test_patch([(0x400734, 'mov edi, 0x400920')])

    def test_cfg_patch_ret_value(self):
        """
        Patch a block to redirect control, but without changing the graph: change return value of `accepted` in rejection branch to 1
        """
        self._test_patch([(0x4006e6, 'mov eax, 1')])

    def test_cfg_patch_branch(self):
        """
        Patch a block, changing the graph: patch `authenticate` to always jump to accept branch, eliminating 1 block.
        """
        self._test_patch([(0x4006dd, 'jne 0x4006df')])

    def test_cfg_patch_call_target(self):
        """
        Patch a block, changing the graph, eliminate a cross reference: change call of `rejected` to `accepted`
        """
        self._test_patch([(0x4007ce, 'call 0x4006ed')])

    #
    # Patches that shrink blocks/function
    #

    def test_cfg_patch_shrink_encoding(self):
        """
        Shorten a block, but do not change graph: use a shorter instruction encoding
        """
        self._test_patch([(0x4006df, 'xor eax, eax;  inc eax;  jmp 0x4006eb')])

    def test_cfg_patch_shrink_branch(self):
        """
        Shorten a block, changing the graph: remove `strcmp` check in `authenticate`, just jump to accept branch
        """
        self._test_patch([(0x4006db, 'jmp 0x4006df')])

    def test_cfg_patch_shrink_ret_value(self):
        """
        Shorten a block, truncating a function: patch `authenticate` to always return 1
        """
        self._test_patch([(0x400664, 'xor rax, rax;  inc rax;  ret')])

    #
    # Patches that grow blocks
    #

    def test_cfg_patch_grow_block_fallthru(self):
        """
        Patch a block to cover another block: ignore return value of `authenticate`, fallthru to accept branch
        """
        self._test_patch([(0x4007bb, 'nop;  nop;')])

    def test_cfg_patch_grow_nocall(self):
        """
        Patch a block to eliminate all cross references to a function: patch out call to `authenticate`, fall thru
        """
        self._test_patch([(0x4007ae, 'xor rax, rax;  nop;  nop')])

    def test_cfg_patch_grow_into_inter_function_padding(self):
        """
        Patch a block to grow into padded space between functions: add `puts("Password: "); return to the end of `main`
        """
        self._test_patch([(0x4007d3, 'mov edi, 0x400920;  call 0x400510;  leave;  ret')])

    def test_cfg_patch_grow_function_fallthru(self):
        """
        Patch a block that extends into another function: cut off the end of `authenticate` so it falls into `accepted`
        """
        self._test_patch([(0x4006ec, 'nop')])
        # Will we have two functions? accepted() is still called so it will probably mark a function


if __name__ == '__main__':
    logging.basicConfig()
    log.setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.cfg.cfg_fast').setLevel(logging.DEBUG)
    logging.getLogger('angr.analyses.cfg.cfg_base').setLevel(logging.DEBUG)
    unittest.main()
